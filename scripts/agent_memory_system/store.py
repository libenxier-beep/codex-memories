"""Private SQLite persistence for captured evidence and pipeline state.

The database is runtime evidence, never durable memory authority.  Every write
method owns one SQLite transaction so callers cannot advance a checkpoint or a
job state independently from the evidence that justifies it.
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .redaction import RedactionPolicy, redact_text, redact_value


SCHEMA_VERSION = 8


class RetentionQuotaExceeded(RuntimeError):
    """A persistence attempt would exceed a hard private-data quota."""


class RetentionPurgeError(RuntimeError):
    """A purge failed atomically and can be retried with the same request ID."""


@dataclass(frozen=True)
class RetentionPolicy:
    """Finite retention and quota limits for every private evidence copy.

    Defaults are deliberately conservative for a single-user local runtime:
    raw evidence and derived offload/candidate data live for at most 30 days;
    sanitized audit receipts live for one year.  Evidence is capped at 20k / 64
    MiB per session and 100k / 256 MiB globally.  The duplicated offload layer is
    capped more tightly.  Callers may lower or raise these finite limits by
    passing an explicit policy to ``AgentMemoryStore``.
    """

    evidence_ttl_seconds: int = 30 * 24 * 60 * 60
    candidate_ttl_seconds: int = 30 * 24 * 60 * 60
    offload_ttl_seconds: int = 30 * 24 * 60 * 60
    receipt_ttl_seconds: int = 365 * 24 * 60 * 60
    evidence_max_count_per_session: int = 20_000
    evidence_max_bytes_per_session: int = 64 * 1024 * 1024
    evidence_max_count_global: int = 100_000
    evidence_max_bytes_global: int = 256 * 1024 * 1024
    offload_max_count_per_session: int = 10_000
    offload_max_bytes_per_session: int = 64 * 1024 * 1024
    offload_max_count_global: int = 50_000
    offload_max_bytes_global: int = 256 * 1024 * 1024
    # Current plus three recent recovery checkpoints. Older full snapshots are
    # derived duplicates: raw content-addressed evidence and sanitized commit /
    # sync receipts remain independently retained.
    task_versions_max_per_task: int = 4
    gc_batch_size: int = 500
    gc_sla_seconds: int = 24 * 60 * 60
    pipeline_error_ttl_seconds: int = 7 * 24 * 60 * 60
    pipeline_error_max_count: int = 1_000
    pipeline_error_max_bytes: int = 1024 * 1024
    pipeline_error_detail_max_bytes: int = 4_096
    pipeline_error_rate_window_seconds: int = 60
    pipeline_error_rate_max_unique: int = 100

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"retention limit {name} must be a positive finite integer")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_id(namespace: str, *parts: object) -> str:
    body = "\x1f".join(str(part) for part in parts)
    return namespace + "_" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _retained_text_bytes(*values: object) -> int:
    return sum(len(str(value if value is not None else "").encode("utf-8")) for value in values)


def _decode_json(value: str | None) -> Any:
    if value is None:
        return None
    return json.loads(value)


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("retention timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _timestamp_before(value: str, seconds: int) -> str:
    return (
        _parse_timestamp(value) - timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _replace_exact_strings(value: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        return replacements.get(value, value)
    if isinstance(value, Mapping):
        return {
            key: _replace_exact_strings(item, replacements)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(_replace_exact_strings(item, replacements) for item in value)
    if isinstance(value, list):
        return [_replace_exact_strings(item, replacements) for item in value]
    return value


def _redact_persisted_text(value: str, policy: RedactionPolicy) -> str:
    """Minimize prose or a serialized JSON wrapper at the store boundary."""

    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return redact_text(value, policy)
    if not isinstance(decoded, (dict, list)):
        return redact_text(value, policy)
    return canonical_json(redact_value(decoded, policy))


class AgentMemoryStore:
    """Durable single-user runtime store with fail-closed transactions."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        retention_policy: RetentionPolicy | None = None,
        redaction_policy: RedactionPolicy | None = None,
    ) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.retention_policy = retention_policy or RetentionPolicy()
        self.redaction_policy = redaction_policy or RedactionPolicy()
        self.database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.database_path.parent, 0o700)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database_path), timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _finalize_physical_purge(self) -> None:
        """Require all deleted WAL frames to be checkpointed and truncated."""

        connection = sqlite3.connect(str(self.database_path), timeout=0.25)
        try:
            connection.execute("PRAGMA busy_timeout = 250")
            connection.execute("PRAGMA secure_delete = ON")
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        finally:
            connection.close()
        if checkpoint is None or int(checkpoint[0]) != 0:
            raise RuntimeError("SQLite WAL remains busy after purge")
        wal_path = Path(str(self.database_path) + "-wal")
        if wal_path.exists() and wal_path.stat().st_size != 0:
            raise RuntimeError("SQLite WAL was not truncated after purge")

    @contextmanager
    def _transaction(self, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    event_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    source_line INTEGER NOT NULL CHECK(source_line > 0),
                    source_line_hash TEXT NOT NULL,
                    evidence_type TEXT NOT NULL CHECK(evidence_type IN ('user','assistant','tool_call','tool_result')),
                    role TEXT,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    occurred_at TEXT,
                    captured_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    UNIQUE(session_id, source_path, source_line, source_line_hash)
                );
                CREATE INDEX IF NOT EXISTS evidence_session_line
                    ON evidence(session_id, source_line);
                CREATE TABLE IF NOT EXISTS capture_event_identities (
                    session_id TEXT NOT NULL,
                    identity_key TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    source_line INTEGER NOT NULL CHECK(source_line > 0),
                    PRIMARY KEY(session_id, identity_key)
                );
                CREATE TABLE IF NOT EXISTS capture_checkpoints (
                    session_id TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    line_number INTEGER NOT NULL CHECK(line_number >= 0),
                    prefix_digest TEXT NOT NULL,
                    byte_offset INTEGER NOT NULL DEFAULT 0 CHECK(byte_offset >= 0),
                    boundary_start INTEGER NOT NULL DEFAULT 0 CHECK(boundary_start >= 0),
                    boundary_digest TEXT NOT NULL DEFAULT '',
                    source_device INTEGER NOT NULL DEFAULT 0,
                    source_inode INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(session_id, source_path)
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    memory_class TEXT NOT NULL CHECK(memory_class IN (
                        'fact','preference','plan','temporary_state','method',
                        'principle','lesson','no_op','deletion_request'
                    )),
                    claim TEXT NOT NULL,
                    normalized_claim TEXT NOT NULL,
                    claim_hash TEXT NOT NULL,
                    slot_key TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('proposed','ignored')),
                    requires_authorization INTEGER NOT NULL CHECK(requires_authorization IN (0,1)),
                    high_impact INTEGER NOT NULL CHECK(high_impact IN (0,1)),
                    expires_at TEXT,
                    source_event_id TEXT NOT NULL REFERENCES evidence(event_id) ON DELETE RESTRICT,
                    source_path TEXT NOT NULL,
                    source_line INTEGER NOT NULL,
                    source_span TEXT NOT NULL,
                    span_start INTEGER NOT NULL,
                    span_end INTEGER NOT NULL,
                    source_text_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_event_id, memory_class, claim_hash)
                );
                CREATE INDEX IF NOT EXISTS candidates_slot ON candidates(slot_key, created_at);
                CREATE TABLE IF NOT EXISTS candidate_relations (
                    relation_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    source_candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id) ON DELETE RESTRICT,
                    target_candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id) ON DELETE RESTRICT,
                    relation_type TEXT NOT NULL CHECK(relation_type IN ('duplicate','conflict','update','supersede','delete')),
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_candidate_id, target_candidate_id, relation_type)
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('pending','leased','succeeded','dead')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
                    available_at TEXT NOT NULL,
                    lease_owner TEXT,
                    lease_until TEXT,
                    result_json TEXT,
                    error_code TEXT,
                    error_detail TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(kind, idempotency_key),
                    CHECK(
                        (status = 'leased' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
                        OR (status != 'leased')
                    )
                );
                CREATE INDEX IF NOT EXISTS jobs_dispatch
                    ON jobs(status, available_at, kind, created_at);
                CREATE TABLE IF NOT EXISTS dead_letters (
                    dead_letter_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
                    attempt INTEGER NOT NULL,
                    error_code TEXT NOT NULL,
                    error_detail TEXT NOT NULL,
                    failed_at TEXT NOT NULL,
                    UNIQUE(job_id, attempt)
                );
                CREATE TABLE IF NOT EXISTS stage_state (
                    stage TEXT PRIMARY KEY,
                    cursor TEXT,
                    status TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pipeline_errors (
                    error_id TEXT PRIMARY KEY,
                    stage TEXT NOT NULL,
                    error_code TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    source_ref TEXT,
                    occurred_at TEXT NOT NULL,
                    fingerprint TEXT,
                    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK(occurrence_count > 0),
                    first_occurred_at TEXT,
                    retained_bytes INTEGER NOT NULL DEFAULT 0 CHECK(retained_bytes >= 0),
                    rate_limited INTEGER NOT NULL DEFAULT 0 CHECK(rate_limited IN (0,1))
                );
                CREATE INDEX IF NOT EXISTS pipeline_errors_time
                    ON pipeline_errors(occurred_at DESC);
                CREATE TABLE IF NOT EXISTS offload_tasks (
                    task_id TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK(version > 0),
                    snapshot_json TEXT NOT NULL,
                    snapshot_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(task_id, version)
                );
                CREATE TABLE IF NOT EXISTS offload_evidence (
                    evidence_ref TEXT PRIMARY KEY,
                    content_sha256 TEXT NOT NULL,
                    encoding TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS offload_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    expected_version INTEGER NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(task_id, version),
                    FOREIGN KEY(task_id, version) REFERENCES offload_tasks(task_id, version)
                        ON DELETE RESTRICT
                );
                CREATE TABLE IF NOT EXISTS offload_sync_state (
                    session_id TEXT PRIMARY KEY,
                    cursor_rowid INTEGER NOT NULL DEFAULT 0 CHECK(cursor_rowid >= 0),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS offload_pending_calls (
                    session_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    call_event_id TEXT NOT NULL UNIQUE,
                    call_rowid INTEGER NOT NULL CHECK(call_rowid > 0),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(session_id, call_id),
                    FOREIGN KEY(call_event_id) REFERENCES evidence(event_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS offload_pair_queue (
                    pair_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    call_id TEXT NOT NULL,
                    call_event_id TEXT NOT NULL,
                    result_event_id TEXT NOT NULL UNIQUE,
                    result_rowid INTEGER NOT NULL CHECK(result_rowid > 0),
                    status TEXT NOT NULL CHECK(status IN ('pending','processed','dead')),
                    step_id TEXT,
                    receipt_json TEXT,
                    error_code TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts > 0),
                    last_error_retryable INTEGER CHECK(last_error_retryable IN (0,1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(call_event_id) REFERENCES evidence(event_id) ON DELETE CASCADE,
                    FOREIGN KEY(result_event_id) REFERENCES evidence(event_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS offload_sync_dead_letters (
                    dead_letter_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    error_code TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES evidence(event_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS retention_usage (
                    storage_class TEXT NOT NULL CHECK(storage_class IN ('evidence','offload')),
                    session_id TEXT NOT NULL,
                    item_count INTEGER NOT NULL CHECK(item_count >= 0),
                    retained_bytes INTEGER NOT NULL CHECK(retained_bytes >= 0),
                    PRIMARY KEY(storage_class, session_id)
                );
                CREATE TABLE IF NOT EXISTS retention_purge_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL CHECK(status IN ('applied','failed')),
                    reason TEXT NOT NULL CHECK(reason IN ('manual','ttl','quota','recovery','authority')),
                    selector_digest TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_restore_tombstones (
                    identity_digest TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('offload_evidence')),
                    purge_receipt_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_replay_tombstones (
                    identity_digest TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_session_tombstones (
                    session_digest TEXT PRIMARY KEY,
                    purge_receipt_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS retention_gc_state (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    last_run_at TEXT,
                    last_success_at TEXT,
                    cursor TEXT,
                    has_more INTEGER NOT NULL DEFAULT 0 CHECK(has_more IN (0,1)),
                    status TEXT NOT NULL DEFAULT 'never_run',
                    last_receipt_id TEXT
                );
                CREATE TABLE IF NOT EXISTS retention_authority_purge_bindings (
                    authority_receipt_digest TEXT PRIMARY KEY,
                    purge_receipt_id TEXT NOT NULL,
                    selector_digest TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );
                """
            )
            legacy_purge_table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='retention_purge_receipts_legacy'"
            ).fetchone()
            if legacy_purge_table is not None:
                # A pre-v7 process could be interrupted after renaming the old
                # table. Recover that durable state before inspecting the live
                # table. INSERT OR IGNORE also closes the after-copy crash state.
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    INSERT OR IGNORE INTO retention_purge_receipts
                    SELECT * FROM retention_purge_receipts_legacy;
                    DROP TABLE retention_purge_receipts_legacy;
                    COMMIT;
                    """
                )
            purge_table_sql = str(
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='retention_purge_receipts'"
                ).fetchone()["sql"]
            )
            if "'authority'" not in purge_table_sql:
                # Schema v4/v5 allowed only lifecycle GC reasons.  Rebuild the
                # receipt table so an applied canonical tombstone can bind its
                # runtime purge without weakening the existing constraints.
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    ALTER TABLE retention_purge_receipts
                        RENAME TO retention_purge_receipts_legacy;
                    CREATE TABLE retention_purge_receipts (
                        receipt_id TEXT PRIMARY KEY,
                        request_id TEXT NOT NULL UNIQUE,
                        status TEXT NOT NULL CHECK(status IN ('applied','failed')),
                        reason TEXT NOT NULL CHECK(reason IN (
                            'manual','ttl','quota','recovery','authority'
                        )),
                        selector_digest TEXT NOT NULL,
                        receipt_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    INSERT INTO retention_purge_receipts
                    SELECT * FROM retention_purge_receipts_legacy;
                    DROP TABLE retention_purge_receipts_legacy;
                    COMMIT;
                    """
                )
            checkpoint_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(capture_checkpoints)")
            }
            # Runtime databases created by schema v1 are upgraded in place.
            # Existing checkpoints intentionally retain byte_offset=0, which
            # makes the capture reader perform one fully verified legacy pass
            # before switching to bounded incremental reads.
            checkpoint_migrations = (
                ("byte_offset", "INTEGER NOT NULL DEFAULT 0"),
                ("boundary_start", "INTEGER NOT NULL DEFAULT 0"),
                ("boundary_digest", "TEXT NOT NULL DEFAULT ''"),
                ("source_device", "INTEGER NOT NULL DEFAULT 0"),
                ("source_inode", "INTEGER NOT NULL DEFAULT 0"),
            )
            for column, declaration in checkpoint_migrations:
                if column not in checkpoint_columns:
                    connection.execute(
                        f"ALTER TABLE capture_checkpoints ADD COLUMN {column} {declaration}"
                    )
            offload_task_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(offload_tasks)")
            }
            for column, declaration in (
                ("session_id", "TEXT"),
                ("retained_bytes", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in offload_task_columns:
                    connection.execute(
                        f"ALTER TABLE offload_tasks ADD COLUMN {column} {declaration}"
                    )
            offload_evidence_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(offload_evidence)")
            }
            for column, declaration in (
                ("session_id", "TEXT"),
                ("retained_bytes", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in offload_evidence_columns:
                    connection.execute(
                        f"ALTER TABLE offload_evidence ADD COLUMN {column} {declaration}"
                    )
            pipeline_error_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(pipeline_errors)")
            }
            for column, declaration in (
                ("fingerprint", "TEXT"),
                ("occurrence_count", "INTEGER NOT NULL DEFAULT 1"),
                ("first_occurred_at", "TEXT"),
                ("retained_bytes", "INTEGER NOT NULL DEFAULT 0"),
                ("rate_limited", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in pipeline_error_columns:
                    connection.execute(
                        f"ALTER TABLE pipeline_errors ADD COLUMN {column} {declaration}"
                    )
            pair_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(offload_pair_queue)")
            }
            for column, declaration in (
                ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("max_attempts", "INTEGER NOT NULL DEFAULT 3"),
                ("last_error_retryable", "INTEGER"),
            ):
                if column not in pair_columns:
                    connection.execute(
                        f"ALTER TABLE offload_pair_queue ADD COLUMN {column} {declaration}"
                    )
            connection.executescript(
                "DROP TRIGGER IF EXISTS evidence_usage_insert;"
                "DROP TRIGGER IF EXISTS evidence_usage_delete;"
            )
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS evidence_captured_at
                    ON evidence(captured_at,event_id);
                CREATE INDEX IF NOT EXISTS evidence_session_captured_at
                    ON evidence(session_id,captured_at,event_id);
                CREATE INDEX IF NOT EXISTS candidates_created_at
                    ON candidates(created_at,candidate_id);
                CREATE INDEX IF NOT EXISTS offload_tasks_retention
                    ON offload_tasks(session_id,created_at,task_id,version);
                CREATE INDEX IF NOT EXISTS offload_evidence_retention
                    ON offload_evidence(session_id,created_at,evidence_ref);
                CREATE INDEX IF NOT EXISTS offload_pair_dispatch
                    ON offload_pair_queue(session_id,status,result_rowid,pair_id);
                CREATE INDEX IF NOT EXISTS purge_receipts_time
                    ON retention_purge_receipts(updated_at,receipt_id);
                CREATE INDEX IF NOT EXISTS restore_tombstones_expiry
                    ON retention_restore_tombstones(expires_at,identity_digest);
                CREATE INDEX IF NOT EXISTS replay_tombstones_expiry
                    ON retention_replay_tombstones(expires_at,identity_digest);
                CREATE INDEX IF NOT EXISTS pipeline_errors_fingerprint
                    ON pipeline_errors(fingerprint,occurred_at DESC);
                CREATE TRIGGER IF NOT EXISTS evidence_usage_insert
                AFTER INSERT ON evidence BEGIN
                    INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes)
                    VALUES('evidence','',1,
                        length(CAST(NEW.event_id AS BLOB))+length(CAST(NEW.session_id AS BLOB))+
                        length(CAST(NEW.source_path AS BLOB))+length(CAST(NEW.source_line AS BLOB))+
                        length(CAST(NEW.source_line_hash AS BLOB))+length(CAST(NEW.evidence_type AS BLOB))+
                        length(CAST(COALESCE(NEW.role,'') AS BLOB))+length(CAST(NEW.content AS BLOB))+
                        length(CAST(NEW.content_hash AS BLOB))+length(CAST(COALESCE(NEW.occurred_at,'') AS BLOB))+
                        length(CAST(NEW.captured_at AS BLOB))+length(CAST(NEW.metadata_json AS BLOB)))
                    ON CONFLICT(storage_class,session_id) DO UPDATE SET
                        item_count=item_count+1,
                        retained_bytes=retained_bytes+excluded.retained_bytes;
                    INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes)
                    VALUES('evidence',NEW.session_id,1,
                        length(CAST(NEW.event_id AS BLOB))+length(CAST(NEW.session_id AS BLOB))+
                        length(CAST(NEW.source_path AS BLOB))+length(CAST(NEW.source_line AS BLOB))+
                        length(CAST(NEW.source_line_hash AS BLOB))+length(CAST(NEW.evidence_type AS BLOB))+
                        length(CAST(COALESCE(NEW.role,'') AS BLOB))+length(CAST(NEW.content AS BLOB))+
                        length(CAST(NEW.content_hash AS BLOB))+length(CAST(COALESCE(NEW.occurred_at,'') AS BLOB))+
                        length(CAST(NEW.captured_at AS BLOB))+length(CAST(NEW.metadata_json AS BLOB)))
                    ON CONFLICT(storage_class,session_id) DO UPDATE SET
                        item_count=item_count+1,
                        retained_bytes=retained_bytes+excluded.retained_bytes;
                END;
                CREATE TRIGGER IF NOT EXISTS evidence_usage_delete
                AFTER DELETE ON evidence BEGIN
                    UPDATE retention_usage SET
                        item_count=item_count-1,
                        retained_bytes=retained_bytes-(
                        length(CAST(OLD.event_id AS BLOB))+length(CAST(OLD.session_id AS BLOB))+
                        length(CAST(OLD.source_path AS BLOB))+length(CAST(OLD.source_line AS BLOB))+
                        length(CAST(OLD.source_line_hash AS BLOB))+length(CAST(OLD.evidence_type AS BLOB))+
                        length(CAST(COALESCE(OLD.role,'') AS BLOB))+length(CAST(OLD.content AS BLOB))+
                        length(CAST(OLD.content_hash AS BLOB))+length(CAST(COALESCE(OLD.occurred_at,'') AS BLOB))+
                        length(CAST(OLD.captured_at AS BLOB))+length(CAST(OLD.metadata_json AS BLOB)))
                    WHERE storage_class='evidence' AND session_id IN ('',OLD.session_id);
                    DELETE FROM retention_usage
                    WHERE storage_class='evidence' AND session_id<>'' AND item_count=0;
                END;
                CREATE TRIGGER IF NOT EXISTS offload_task_usage_insert
                AFTER INSERT ON offload_tasks BEGIN
                    INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes)
                    VALUES('offload','',1,NEW.retained_bytes)
                    ON CONFLICT(storage_class,session_id) DO UPDATE SET
                        item_count=item_count+1,
                        retained_bytes=retained_bytes+excluded.retained_bytes;
                    INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes)
                    SELECT 'offload',NEW.session_id,1,NEW.retained_bytes
                    WHERE NEW.session_id IS NOT NULL AND NEW.session_id<>''
                    ON CONFLICT(storage_class,session_id) DO UPDATE SET
                        item_count=item_count+1,
                        retained_bytes=retained_bytes+excluded.retained_bytes;
                END;
                CREATE TRIGGER IF NOT EXISTS offload_task_usage_delete
                AFTER DELETE ON offload_tasks BEGIN
                    UPDATE retention_usage SET
                        item_count=item_count-1,
                        retained_bytes=retained_bytes-OLD.retained_bytes
                    WHERE storage_class='offload' AND
                        (session_id='' OR session_id=COALESCE(OLD.session_id,''));
                    DELETE FROM retention_usage
                    WHERE storage_class='offload' AND session_id<>'' AND item_count=0;
                END;
                CREATE TRIGGER IF NOT EXISTS offload_evidence_usage_insert
                AFTER INSERT ON offload_evidence BEGIN
                    INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes)
                    VALUES('offload','',1,NEW.retained_bytes)
                    ON CONFLICT(storage_class,session_id) DO UPDATE SET
                        item_count=item_count+1,
                        retained_bytes=retained_bytes+excluded.retained_bytes;
                    INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes)
                    SELECT 'offload',NEW.session_id,1,NEW.retained_bytes
                    WHERE NEW.session_id IS NOT NULL AND NEW.session_id<>''
                    ON CONFLICT(storage_class,session_id) DO UPDATE SET
                        item_count=item_count+1,
                        retained_bytes=retained_bytes+excluded.retained_bytes;
                END;
                CREATE TRIGGER IF NOT EXISTS offload_evidence_usage_delete
                AFTER DELETE ON offload_evidence BEGIN
                    UPDATE retention_usage SET
                        item_count=item_count-1,
                        retained_bytes=retained_bytes-OLD.retained_bytes
                    WHERE storage_class='offload' AND
                        (session_id='' OR session_id=COALESCE(OLD.session_id,''));
                    DELETE FROM retention_usage
                    WHERE storage_class='offload' AND session_id<>'' AND item_count=0;
                END;
                """
            )
            connection.execute(
                "UPDATE offload_tasks SET retained_bytes=length(CAST(snapshot_json AS BLOB)) "
                "WHERE retained_bytes=0"
            )
            connection.execute(
                "UPDATE offload_evidence SET retained_bytes=length(CAST(payload AS BLOB))+"
                "length(CAST(evidence_json AS BLOB)) "
                "WHERE retained_bytes=0"
            )
            connection.execute(
                "UPDATE pipeline_errors SET fingerprint=error_id WHERE fingerprint IS NULL"
            )
            connection.execute(
                "UPDATE pipeline_errors SET first_occurred_at=occurred_at "
                "WHERE first_occurred_at IS NULL"
            )
            connection.execute(
                "UPDATE pipeline_errors SET retained_bytes="
                "length(CAST(detail AS BLOB))+length(CAST(COALESCE(source_ref,'') AS BLOB)) "
                "WHERE retained_bytes=0"
            )
            # Rebuild counters once on open from canonical rows. Subsequent
            # inserts, deletes, purge cascades and transaction rollbacks are
            # maintained atomically by the triggers above, keeping hot-path
            # quota checks independent of retained history size.
            connection.execute("DELETE FROM retention_usage")
            connection.execute(
                "INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes) "
                "SELECT 'evidence','',COUNT(*),COALESCE(SUM("
                "length(CAST(event_id AS BLOB))+length(CAST(session_id AS BLOB))+"
                "length(CAST(source_path AS BLOB))+length(CAST(source_line AS BLOB))+"
                "length(CAST(source_line_hash AS BLOB))+length(CAST(evidence_type AS BLOB))+"
                "length(CAST(COALESCE(role,'') AS BLOB))+length(CAST(content AS BLOB))+"
                "length(CAST(content_hash AS BLOB))+length(CAST(COALESCE(occurred_at,'') AS BLOB))+"
                "length(CAST(captured_at AS BLOB))+length(CAST(metadata_json AS BLOB))),0) "
                "FROM evidence"
            )
            connection.execute(
                "INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes) "
                "SELECT 'evidence',session_id,COUNT(*),"
                "COALESCE(SUM(length(CAST(event_id AS BLOB))+length(CAST(session_id AS BLOB))+"
                "length(CAST(source_path AS BLOB))+length(CAST(source_line AS BLOB))+"
                "length(CAST(source_line_hash AS BLOB))+length(CAST(evidence_type AS BLOB))+"
                "length(CAST(COALESCE(role,'') AS BLOB))+length(CAST(content AS BLOB))+"
                "length(CAST(content_hash AS BLOB))+length(CAST(COALESCE(occurred_at,'') AS BLOB))+"
                "length(CAST(captured_at AS BLOB))+length(CAST(metadata_json AS BLOB))),0) "
                "FROM evidence GROUP BY session_id"
            )
            connection.execute(
                "INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes) "
                "SELECT 'offload','',COUNT(*),COALESCE(SUM(retained_bytes),0) FROM ("
                "SELECT retained_bytes FROM offload_tasks UNION ALL "
                "SELECT retained_bytes FROM offload_evidence)"
            )
            connection.execute(
                "INSERT INTO retention_usage(storage_class,session_id,item_count,retained_bytes) "
                "SELECT 'offload',session_id,COUNT(*),COALESCE(SUM(retained_bytes),0) FROM ("
                "SELECT session_id,retained_bytes FROM offload_tasks WHERE session_id IS NOT NULL "
                "UNION ALL SELECT session_id,retained_bytes FROM offload_evidence "
                "WHERE session_id IS NOT NULL) GROUP BY session_id"
            )
            for row in connection.execute(
                "SELECT receipt_id,selector_digest,receipt_json,updated_at "
                "FROM retention_purge_receipts WHERE status='applied' AND reason='authority'"
            ):
                try:
                    receipt = json.loads(str(row["receipt_json"]))
                except json.JSONDecodeError:
                    continue
                authority_digest = receipt.get("authority_receipt_digest")
                if isinstance(authority_digest, str) and len(authority_digest) == 64:
                    connection.execute(
                        "INSERT OR IGNORE INTO retention_authority_purge_bindings("
                        "authority_receipt_digest,purge_receipt_id,selector_digest,applied_at) "
                        "VALUES(?,?,?,?)",
                        (authority_digest, row["receipt_id"], row["selector_digest"], row["updated_at"]),
                    )
            connection.execute(
                "INSERT OR REPLACE INTO schema_metadata(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            backfilled = connection.execute(
                "SELECT value FROM schema_metadata WHERE key='capture_event_identities_backfilled'"
            ).fetchone()
            if backfilled is None:
                rows = connection.execute(
                    "SELECT event_id,session_id,evidence_type,source_line_hash,source_line,metadata_json FROM evidence"
                ).fetchall()
                for row in rows:
                    metadata = _decode_json(row["metadata_json"])
                    source_event_id = metadata.get("source_event_id") if isinstance(metadata, dict) else None
                    if isinstance(source_event_id, str) and source_event_id:
                        kind, value = "source_event_id", source_event_id
                    else:
                        kind, value = "source_line_hash", str(row["source_line_hash"])
                    identity_key = stable_id("replay", row["evidence_type"], kind, value)
                    connection.execute(
                        "INSERT OR IGNORE INTO capture_event_identities VALUES(?,?,?,?)",
                        (row["session_id"], identity_key, row["event_id"], row["source_line"]),
                    )
                connection.execute(
                    "INSERT INTO schema_metadata(key,value) VALUES('capture_event_identities_backfilled','1')"
                )
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.database_path, 0o600)

    def capture_batch(
        self,
        *,
        session_id: str,
        source_path: str | Path,
        records: Sequence[Mapping[str, Any]],
        checkpoint_line: int,
        prefix_digest: str,
        byte_offset: int,
        boundary_start: int,
        boundary_digest: str,
        source_device: int,
        source_inode: int,
        updated_at: str | None = None,
    ) -> tuple[int, int]:
        """Insert evidence and advance its checkpoint atomically."""
        if (
            not session_id
            or checkpoint_line < 0
            or len(prefix_digest) != 64
            or byte_offset < 0
            or boundary_start < 0
            or boundary_start > byte_offset
            or len(boundary_digest) != 64
            or source_device < 0
            or source_inode < 0
        ):
            raise ValueError("invalid capture batch identity or checkpoint")
        path = str(Path(source_path).expanduser().resolve())
        stamp = updated_at or utc_now()
        sanitized_records = [self._redacted_capture_record(record) for record in records]
        inserted = 0
        with self._transaction() as connection:
            self._require_session_capture_allowed_tx(connection, session_id)
            incoming_identities = list(
                dict.fromkeys(str(record["replay_identity"]) for record in sanitized_records)
            )
            blocked_replay_identities = self._blocked_replay_identities_tx(
                connection, session_id, incoming_identities, stamp
            )
            if sanitized_records and all(
                str(record["replay_identity"]) in blocked_replay_identities
                for record in sanitized_records
            ):
                return 0, len(sanitized_records)
            existing_identities = set(blocked_replay_identities)
            for offset in range(0, len(incoming_identities), 500):
                batch = incoming_identities[offset : offset + 500]
                if not batch:
                    continue
                placeholders = ",".join("?" for _ in batch)
                existing_identities.update(
                    str(row["identity_key"])
                    for row in connection.execute(
                        "SELECT identity_key FROM capture_event_identities "
                        f"WHERE session_id=? AND identity_key IN ({placeholders})",
                        (session_id, *batch),
                    ).fetchall()
                )
            seen_quota_identities: set[str] = set()
            quota_records = []
            for record in sanitized_records:
                identity = str(record["replay_identity"])
                if identity in existing_identities or identity in seen_quota_identities:
                    continue
                seen_quota_identities.add(identity)
                quota_records.append(record)
            self._ensure_evidence_quota(
                connection,
                session_id,
                incoming_count=len(quota_records),
                incoming_bytes=sum(
                    _retained_text_bytes(
                        record["event_id"], session_id, path, record["source_line"],
                        record["source_line_hash"], record["evidence_type"],
                        record.get("role"), record["content"], record["content_hash"],
                        record.get("occurred_at"), stamp,
                        canonical_json(record.get("metadata", {})),
                    )
                    for record in quota_records
                ),
            )
            for record in sanitized_records:
                if str(record["replay_identity"]) in blocked_replay_identities:
                    continue
                identity = connection.execute(
                    """
                    INSERT OR IGNORE INTO capture_event_identities(
                        session_id,identity_key,event_id,source_line
                    ) VALUES(?,?,?,?)
                    """,
                    (
                        session_id,
                        record["replay_identity"],
                        record["event_id"],
                        record["source_line"],
                    ),
                )
                if identity.rowcount == 0:
                    continue
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO evidence(
                        event_id,session_id,source_path,source_line,source_line_hash,
                        evidence_type,role,content,content_hash,occurred_at,captured_at,metadata_json
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["event_id"], session_id, path, record["source_line"],
                        record["source_line_hash"], record["evidence_type"], record.get("role"),
                        record["content"], record["content_hash"], record.get("occurred_at"), stamp,
                        canonical_json(record.get("metadata", {})),
                    ),
                )
                inserted += cursor.rowcount
            connection.execute(
                """
                INSERT INTO capture_checkpoints(
                    session_id,source_path,line_number,prefix_digest,byte_offset,
                    boundary_start,boundary_digest,source_device,source_inode,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(session_id,source_path) DO UPDATE SET
                    line_number=excluded.line_number,
                    prefix_digest=excluded.prefix_digest,
                    byte_offset=excluded.byte_offset,
                    boundary_start=excluded.boundary_start,
                    boundary_digest=excluded.boundary_digest,
                    source_device=excluded.source_device,
                    source_inode=excluded.source_inode,
                    updated_at=excluded.updated_at
                """,
                (
                    session_id, path, checkpoint_line, prefix_digest, byte_offset,
                    boundary_start, boundary_digest, source_device, source_inode, stamp,
                ),
            )
            if inserted:
                key = f"{session_id}:{checkpoint_line}:{prefix_digest}"
                job_id = stable_id("job", "distill", key)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO jobs(
                        job_id,kind,idempotency_key,payload_json,status,attempts,max_attempts,
                        available_at,created_at,updated_at
                    ) VALUES(?,?,?,?, 'pending',0,3,?,?,?)
                    """,
                    (
                        job_id, "distill", key,
                        canonical_json({"session_id": session_id, "checkpoint_line": checkpoint_line}),
                        stamp, stamp, stamp,
                    ),
                )
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at) VALUES('capture',?,'ok',?)
                ON CONFLICT(stage) DO UPDATE SET cursor=excluded.cursor,status='ok',updated_at=excluded.updated_at
                """,
                (f"{session_id}:{checkpoint_line}", stamp),
            )
        return inserted, len(sanitized_records) - inserted

    def get_capture_identity_source(
        self, session_id: str, identity_key: str
    ) -> int | None:
        return self.get_capture_identity_sources(session_id, (identity_key,)).get(identity_key)

    def capture_hook_prompt(
        self,
        *,
        session_id: str,
        prompt: str,
        cwd: str,
        source_event_id: str | None = None,
        occurred_at: str | None = None,
        updated_at: str | None = None,
    ) -> dict[str, Any]:
        """Atomically persist one real UserPromptSubmit observation.

        Current Codex host payloads do not expose a transcript path.  The hook
        event is therefore its own private evidence source.  A host event ID is
        preferred for replay identity; when unavailable an exact prompt hash is
        the conservative retry key, so a retried callback cannot duplicate a
        candidate.
        """

        if not session_id or not prompt.strip() or not cwd or "\x00" in session_id + cwd:
            raise ValueError("invalid hook prompt evidence")
        if len(prompt.encode("utf-8")) > 1024 * 1024:
            raise ValueError("hook prompt exceeds capture limit")
        source_prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        retained_prompt = _redact_persisted_text(prompt, self.redaction_policy)
        retained_prompt_hash = hashlib.sha256(retained_prompt.encode("utf-8")).hexdigest()
        source_identity = source_event_id or stable_id(
            "hook-prompt", session_id, source_prompt_hash
        )
        if "\x00" in source_identity:
            raise ValueError("invalid hook source event identity")
        identity_key = stable_id(
            "replay", "user", "source_event_id", source_identity
        )
        event_id = stable_id("evt", session_id, "UserPromptSubmit", source_identity)
        source_path = "codex-hook://UserPromptSubmit"
        stamp = updated_at or utc_now()
        stored_metadata_json = canonical_json(
            redact_value(
                {
                    "source_event_id": source_identity,
                    "hook_event_name": "UserPromptSubmit",
                    "cwd": cwd,
                },
                self.redaction_policy,
            )
        )
        with self._transaction() as connection:
            self._require_session_capture_allowed_tx(connection, session_id)
            if self._replay_identity_blocked_tx(
                connection, session_id, identity_key, stamp
            ):
                return {
                    "event_id": event_id,
                    "source_line": 0,
                    "captured": 0,
                    "duplicates": 1,
                }
            existing = connection.execute(
                "SELECT event_id,source_line FROM capture_event_identities "
                "WHERE session_id=? AND identity_key=?",
                (session_id, identity_key),
            ).fetchone()
            if existing is not None:
                return {
                    "event_id": str(existing["event_id"]),
                    "source_line": int(existing["source_line"]),
                    "captured": 0,
                    "duplicates": 1,
                }
            source_line = int(
                connection.execute(
                    "SELECT COALESCE(MAX(source_line),0)+1 FROM evidence "
                    "WHERE session_id=? AND source_path=?",
                    (session_id, source_path),
                ).fetchone()[0]
            )
            self._ensure_evidence_quota(
                connection,
                session_id,
                incoming_count=1,
                incoming_bytes=_retained_text_bytes(
                    event_id, session_id, source_path, source_line, source_prompt_hash,
                    "user", "user", retained_prompt, retained_prompt_hash,
                    occurred_at, stamp, stored_metadata_json,
                ),
            )
            connection.execute(
                "INSERT INTO capture_event_identities(session_id,identity_key,event_id,source_line) "
                "VALUES(?,?,?,?)",
                (session_id, identity_key, event_id, source_line),
            )
            connection.execute(
                """
                INSERT INTO evidence(
                    event_id,session_id,source_path,source_line,source_line_hash,
                    evidence_type,role,content,content_hash,occurred_at,captured_at,metadata_json
                ) VALUES(?,?,?,?,?,'user','user',?,?,?,?,?)
                """,
                (
                    event_id,
                    session_id,
                    source_path,
                    source_line,
                    source_prompt_hash,
                    retained_prompt,
                    retained_prompt_hash,
                    occurred_at,
                    stamp,
                    stored_metadata_json,
                ),
            )
            job_key = "{}:{}:{}".format(session_id, source_line, source_identity)
            job_id = stable_id("job", "distill", job_key)
            connection.execute(
                """
                INSERT OR IGNORE INTO jobs(
                    job_id,kind,idempotency_key,payload_json,status,attempts,max_attempts,
                    available_at,created_at,updated_at
                ) VALUES(?,?,?,?, 'pending',0,3,?,?,?)
                """,
                (
                    job_id,
                    "distill",
                    job_key,
                    canonical_json(
                        {"session_id": session_id, "checkpoint_line": source_line}
                    ),
                    stamp,
                    stamp,
                    stamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at)
                VALUES('capture',?,'ok',?)
                ON CONFLICT(stage) DO UPDATE SET
                    cursor=excluded.cursor,status='ok',updated_at=excluded.updated_at
                """,
                ("{}:hook:{}".format(session_id, source_line), stamp),
            )
        return {
            "event_id": event_id,
            "source_line": source_line,
            "captured": 1,
            "duplicates": 0,
        }

    def capture_hook_observation(
        self,
        *,
        session_id: str,
        event_name: str,
        evidence_type: str,
        role: str | None,
        content: str,
        cwd: str,
        source_event_id: str,
        metadata: Mapping[str, Any] | None = None,
        queue_distill: bool = False,
        occurred_at: str | None = None,
        updated_at: str | None = None,
    ) -> dict[str, Any]:
        """Persist one non-prompt Codex hook observation idempotently."""

        if (
            not session_id
            or event_name not in {"PreToolUse", "PostToolUse", "Stop"}
            or evidence_type not in {"assistant", "tool_call", "tool_result"}
            or not content
            or not cwd
            or not source_event_id
            or "\x00" in session_id + event_name + cwd + source_event_id
        ):
            raise ValueError("invalid hook observation")
        if len(content.encode("utf-8")) > 8 * 1024 * 1024:
            raise ValueError("hook observation exceeds capture limit")
        if queue_distill and not (event_name == "Stop" and evidence_type == "assistant"):
            raise ValueError("only assistant Stop observations can queue distillation")
        source_path = "codex-hook://{}".format(event_name)
        source_content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        retained_content = _redact_persisted_text(content, self.redaction_policy)
        retained_content_hash = hashlib.sha256(retained_content.encode("utf-8")).hexdigest()
        identity_key = stable_id(
            "replay", evidence_type, "source_event_id", source_event_id
        )
        event_id = stable_id(
            "evt", session_id, event_name, evidence_type, source_event_id
        )
        stamp = updated_at or utc_now()
        stored_metadata = dict(metadata or {})
        stored_metadata.update(
            {
                "source_event_id": source_event_id,
                "hook_event_name": event_name,
                "cwd": cwd,
            }
        )
        stored_metadata = redact_value(stored_metadata, self.redaction_policy)
        stored_metadata_json = canonical_json(stored_metadata)
        with self._transaction() as connection:
            self._require_session_capture_allowed_tx(connection, session_id)
            if self._replay_identity_blocked_tx(
                connection, session_id, identity_key, stamp
            ):
                return {
                    "event_id": event_id,
                    "source_line": 0,
                    "captured": 0,
                    "duplicates": 1,
                }
            existing = connection.execute(
                "SELECT event_id,source_line FROM capture_event_identities "
                "WHERE session_id=? AND identity_key=?",
                (session_id, identity_key),
            ).fetchone()
            if existing is not None:
                return {
                    "event_id": str(existing["event_id"]),
                    "source_line": int(existing["source_line"]),
                    "captured": 0,
                    "duplicates": 1,
                }
            source_line = int(
                connection.execute(
                    "SELECT COALESCE(MAX(source_line),0)+1 FROM evidence "
                    "WHERE session_id=? AND source_path=?",
                    (session_id, source_path),
                ).fetchone()[0]
            )
            self._ensure_evidence_quota(
                connection,
                session_id,
                incoming_count=1,
                incoming_bytes=_retained_text_bytes(
                    event_id, session_id, source_path, source_line, source_content_hash,
                    evidence_type, role, retained_content, retained_content_hash,
                    occurred_at, stamp, stored_metadata_json,
                ),
            )
            connection.execute(
                "INSERT INTO capture_event_identities(session_id,identity_key,event_id,source_line) "
                "VALUES(?,?,?,?)",
                (session_id, identity_key, event_id, source_line),
            )
            connection.execute(
                """
                INSERT INTO evidence(
                    event_id,session_id,source_path,source_line,source_line_hash,
                    evidence_type,role,content,content_hash,occurred_at,captured_at,metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    session_id,
                    source_path,
                    source_line,
                    source_content_hash,
                    evidence_type,
                    role,
                    retained_content,
                    retained_content_hash,
                    occurred_at,
                    stamp,
                    stored_metadata_json,
                ),
            )
            if queue_distill:
                job_key = "{}:{}:{}:assistant-stop".format(
                    session_id, source_line, source_event_id
                )
                job_id = stable_id("job", "distill", job_key)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO jobs(
                        job_id,kind,idempotency_key,payload_json,status,attempts,max_attempts,
                        available_at,created_at,updated_at
                    ) VALUES(?,?,?,?, 'pending',0,3,?,?,?)
                    """,
                    (
                        job_id,
                        "distill",
                        job_key,
                        canonical_json(
                            {"session_id": session_id, "checkpoint_line": source_line}
                        ),
                        stamp,
                        stamp,
                        stamp,
                    ),
                )
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at)
                VALUES('capture',?,'ok',?)
                ON CONFLICT(stage) DO UPDATE SET
                    cursor=excluded.cursor,status='ok',updated_at=excluded.updated_at
                """,
                (
                    "{}:{}:{}".format(session_id, event_name, source_line),
                    stamp,
                ),
            )
        return {
            "event_id": event_id,
            "source_line": source_line,
            "captured": 1,
            "duplicates": 0,
        }

    def get_capture_identity_sources(
        self, session_id: str, identity_keys: Sequence[str]
    ) -> dict[str, int]:
        unique_keys = list(dict.fromkeys(identity_keys))
        result: dict[str, int] = {}
        with self._connect() as connection:
            blocked = self._blocked_replay_identities_tx(
                connection, session_id, unique_keys, utc_now(), cleanup=False
            )
            result.update({key: 0 for key in blocked})
            for offset in range(0, len(unique_keys), 500):
                batch = [
                    key for key in unique_keys[offset : offset + 500]
                    if key not in blocked
                ]
                if not batch:
                    continue
                placeholders = ",".join("?" for _ in batch)
                rows = connection.execute(
                    "SELECT identity_key,source_line FROM capture_event_identities "
                    "WHERE session_id=? AND identity_key IN ({})".format(placeholders),
                    (session_id, *batch),
                ).fetchall()
                result.update(
                    {str(row["identity_key"]): int(row["source_line"]) for row in rows}
                )
        return result

    def get_checkpoint(self, session_id: str, source_path: str | Path) -> dict[str, Any] | None:
        path = str(Path(source_path).expanduser().resolve())
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM capture_checkpoints WHERE session_id=? AND source_path=?",
                (session_id, path),
            ).fetchone()
        return dict(row) if row else None

    def list_evidence(self, session_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM evidence"
        parameters: tuple[object, ...] = ()
        if session_id is not None:
            sql += " WHERE session_id=?"
            parameters = (session_id,)
        sql += " ORDER BY rowid"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["metadata"] = _decode_json(item.pop("metadata_json"))
            result.append(item)
        return result

    def list_task_invariant_sources(
        self, session_id: str, *, limit: int = 32
    ) -> list[dict[str, Any]]:
        """Return a bounded user-only source set for TaskInvariant derivation."""

        if not session_id or "\x00" in session_id or limit < 1 or limit > 128:
            raise ValueError("invalid task invariant source query")
        with self._connect() as connection:
            first = connection.execute(
                "SELECT rowid AS evidence_rowid,* FROM evidence "
                "WHERE session_id=? AND evidence_type='user' AND role='user' "
                "ORDER BY rowid ASC LIMIT 1",
                (session_id,),
            ).fetchone()
            recent = connection.execute(
                "SELECT rowid AS evidence_rowid,* FROM evidence "
                "WHERE session_id=? AND evidence_type='user' AND role='user' "
                "ORDER BY rowid DESC LIMIT ?",
                (session_id, limit),
            ).fetchall()
        rows = {str(row["event_id"]): row for row in recent}
        if first is not None:
            rows[str(first["event_id"])] = first
        result = []
        for row in sorted(rows.values(), key=lambda item: int(item["evidence_rowid"])):
            value = dict(row)
            value["metadata"] = _decode_json(value.pop("metadata_json"))
            result.append(value)
        return result

    def ingest_offload_sync_delta(
        self,
        session_id: str,
        *,
        limit: int = 256,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Pair only newly captured tool evidence and durably advance its cursor.

        The cursor, pending-call state, pair queue, and malformed-event DLQ are
        committed in one transaction.  Queue payloads retain only event IDs;
        raw tool prose remains solely in the governed evidence table.
        """

        if not session_id or "\x00" in session_id or limit < 1 or limit > 1_000:
            raise ValueError("invalid offload sync scan")
        stamp = now or utc_now()
        with self._transaction() as connection:
            state = connection.execute(
                "SELECT cursor_rowid FROM offload_sync_state WHERE session_id=?",
                (session_id,),
            ).fetchone()
            cursor = int(state["cursor_rowid"]) if state is not None else 0
            selected = connection.execute(
                "SELECT rowid AS evidence_rowid,event_id,evidence_type,metadata_json "
                "FROM evidence WHERE session_id=? AND rowid>? ORDER BY rowid LIMIT ?",
                (session_id, cursor, limit + 1),
            ).fetchall()
            has_more = len(selected) > limit
            rows = selected[:limit]
            metadata_decodes = 0
            pairs_queued = 0
            dead_lettered = 0
            for row in rows:
                evidence_type = str(row["evidence_type"])
                if evidence_type not in {"tool_call", "tool_result"}:
                    continue
                metadata_decodes += 1
                try:
                    metadata = _decode_json(row["metadata_json"])
                except (json.JSONDecodeError, TypeError):
                    metadata = None
                call_id = metadata.get("call_id") if isinstance(metadata, dict) else None
                if not isinstance(call_id, str) or not call_id or "\x00" in call_id:
                    self._insert_offload_sync_dead_letter(
                        connection,
                        session_id=session_id,
                        event_id=str(row["event_id"]),
                        error_code="missing_call_id",
                        created_at=stamp,
                    )
                    dead_lettered += 1
                    continue
                if evidence_type == "tool_call":
                    existing = connection.execute(
                        "SELECT call_event_id FROM offload_pending_calls "
                        "WHERE session_id=? AND call_id=?",
                        (session_id, call_id),
                    ).fetchone()
                    if existing is not None and str(existing["call_event_id"]) != str(row["event_id"]):
                        self._insert_offload_sync_dead_letter(
                            connection,
                            session_id=session_id,
                            event_id=str(existing["call_event_id"]),
                            error_code="duplicate_call_id",
                            created_at=stamp,
                        )
                        self._insert_offload_sync_dead_letter(
                            connection,
                            session_id=session_id,
                            event_id=str(row["event_id"]),
                            error_code="duplicate_call_id",
                            created_at=stamp,
                        )
                        connection.execute(
                            "DELETE FROM offload_pending_calls WHERE session_id=? AND call_id=?",
                            (session_id, call_id),
                        )
                        dead_lettered += 2
                        continue
                    connection.execute(
                        "INSERT OR IGNORE INTO offload_pending_calls("
                        "session_id,call_id,call_event_id,call_rowid,created_at) VALUES(?,?,?,?,?)",
                        (
                            session_id,
                            call_id,
                            str(row["event_id"]),
                            int(row["evidence_rowid"]),
                            stamp,
                        ),
                    )
                    continue
                pending = connection.execute(
                    "SELECT call_event_id FROM offload_pending_calls "
                    "WHERE session_id=? AND call_id=?",
                    (session_id, call_id),
                ).fetchone()
                if pending is None:
                    self._insert_offload_sync_dead_letter(
                        connection,
                        session_id=session_id,
                        event_id=str(row["event_id"]),
                        error_code="unmatched_tool_result",
                        created_at=stamp,
                    )
                    dead_lettered += 1
                    continue
                call_event_id = str(pending["call_event_id"])
                result_event_id = str(row["event_id"])
                pair_id = stable_id(
                    "offload-pair", session_id, call_id, call_event_id, result_event_id
                )
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO offload_pair_queue("
                    "pair_id,session_id,call_id,call_event_id,result_event_id,result_rowid,"
                    "status,created_at,updated_at) VALUES(?,?,?,?,?,?,'pending',?,?)",
                    (
                        pair_id,
                        session_id,
                        call_id,
                        call_event_id,
                        result_event_id,
                        int(row["evidence_rowid"]),
                        stamp,
                        stamp,
                    ),
                )
                pairs_queued += inserted.rowcount
                connection.execute(
                    "DELETE FROM offload_pending_calls WHERE session_id=? AND call_id=?",
                    (session_id, call_id),
                )
            next_cursor = int(rows[-1]["evidence_rowid"]) if rows else cursor
            connection.execute(
                "INSERT INTO offload_sync_state(session_id,cursor_rowid,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(session_id) DO UPDATE SET "
                "cursor_rowid=excluded.cursor_rowid,updated_at=excluded.updated_at",
                (session_id, next_cursor, stamp),
            )
        return {
            "cursor_rowid": next_cursor,
            "rows_read": len(rows),
            "metadata_decodes": metadata_decodes,
            "pairs_queued": pairs_queued,
            "dead_lettered": dead_lettered,
            "has_more": has_more,
            "scan_queries": 1,
        }

    def next_offload_sync_pair(self, session_id: str) -> dict[str, Any] | None:
        """Return the oldest durable pair with its two authoritative rows."""

        if not session_id or "\x00" in session_id:
            raise ValueError("invalid offload sync session")
        with self._transaction() as connection:
            pair = connection.execute(
                "SELECT * FROM offload_pair_queue "
                "WHERE session_id=? AND status='pending' "
                "ORDER BY result_rowid,pair_id LIMIT 1",
                (session_id,),
            ).fetchone()
            if pair is None:
                return None
            attempt = int(pair["attempts"]) + 1
            connection.execute(
                "UPDATE offload_pair_queue SET attempts=?,updated_at=? "
                "WHERE pair_id=? AND status='pending'",
                (attempt, utc_now(), str(pair["pair_id"])),
            )
            rows = connection.execute(
                "SELECT * FROM evidence WHERE event_id IN (?,?)",
                (str(pair["call_event_id"]), str(pair["result_event_id"])),
            ).fetchall()
        evidence = {str(row["event_id"]): self._evidence_dict(row) for row in rows}
        call = evidence.get(str(pair["call_event_id"]))
        result = evidence.get(str(pair["result_event_id"]))
        if call is None or result is None:
            raise ValueError("offload pair evidence is missing")
        return {
            "pair_id": str(pair["pair_id"]),
            "session_id": session_id,
            "call_id": str(pair["call_id"]),
            "call": call,
            "result": result,
            "attempt": attempt,
            "max_attempts": int(pair["max_attempts"]),
            "evidence_decodes": 2,
        }

    def complete_offload_sync_pair(
        self,
        pair_id: str,
        *,
        step_id: str,
        receipt: Mapping[str, Any],
        now: str | None = None,
    ) -> dict[str, Any]:
        """Idempotently acknowledge a pair after its task snapshot is durable."""

        if not pair_id or not step_id or "\x00" in pair_id + step_id:
            raise ValueError("invalid offload sync receipt")
        stamp = now or utc_now()
        if "receipt_sha256" in receipt:
            raise ValueError("offload sync receipt digest is store-owned")
        safe_receipt = redact_value(dict(receipt), self.redaction_policy)
        safe_receipt["receipt_sha256"] = hashlib.sha256(
            canonical_json(safe_receipt).encode("utf-8")
        ).hexdigest()
        receipt_json = canonical_json(safe_receipt)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT status,step_id,receipt_json FROM offload_pair_queue WHERE pair_id=?",
                (pair_id,),
            ).fetchone()
            if row is None:
                raise ValueError("offload sync pair does not exist")
            if row["status"] == "processed":
                if row["step_id"] != step_id or row["receipt_json"] != receipt_json:
                    raise ValueError("offload sync receipt collision")
                return dict(safe_receipt)
            if row["status"] != "pending":
                raise ValueError("dead offload sync pair cannot be completed")
            connection.execute(
                "UPDATE offload_pair_queue SET status='processed',step_id=?,receipt_json=?,"
                "error_code=NULL,updated_at=? WHERE pair_id=? AND status='pending'",
                (step_id, receipt_json, stamp, pair_id),
            )
        return dict(safe_receipt)

    def dead_letter_offload_sync_pair(
        self,
        pair_id: str,
        error_code: str,
        *,
        now: str | None = None,
    ) -> None:
        self.fail_offload_sync_pair(
            pair_id, error_code, retryable=False, now=now
        )

    def fail_offload_sync_pair(
        self,
        pair_id: str,
        error_code: str,
        *,
        retryable: bool,
        max_attempts: int | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        """Persist retry classification and terminally DLQ exhausted pairs."""

        if not pair_id or not error_code:
            raise ValueError("invalid offload sync failure")
        if max_attempts is not None and max_attempts <= 0:
            raise ValueError("offload sync max_attempts must be positive")
        stamp = now or utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT session_id,result_event_id,status,attempts,max_attempts "
                "FROM offload_pair_queue WHERE pair_id=?",
                (pair_id,),
            ).fetchone()
            if row is None:
                raise ValueError("offload sync pair does not exist")
            attempts = int(row["attempts"])
            effective_max = max_attempts or int(row["max_attempts"])
            if row["status"] != "pending":
                return {
                    "pair_id": pair_id,
                    "status": str(row["status"]),
                    "attempts": attempts,
                    "max_attempts": effective_max,
                    "retryable": bool(retryable),
                }
            terminal = not retryable or attempts >= effective_max
            status = "dead" if terminal else "pending"
            connection.execute(
                "UPDATE offload_pair_queue SET status=?,error_code=?,max_attempts=?,"
                "last_error_retryable=?,updated_at=? "
                "WHERE pair_id=?",
                (status, error_code, effective_max, int(retryable), stamp, pair_id),
            )
            if terminal:
                self._insert_offload_sync_dead_letter(
                    connection,
                    session_id=str(row["session_id"]),
                    event_id=str(row["result_event_id"]),
                    error_code=error_code,
                    created_at=stamp,
                )
        return {
            "pair_id": pair_id,
            "status": status,
            "attempts": attempts,
            "max_attempts": effective_max,
            "retryable": bool(retryable),
        }

    def list_offload_sync_receipts(
        self, *, session_id: str | None = None
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT pair_id,session_id,call_id,step_id,receipt_json,updated_at "
            "FROM offload_pair_queue WHERE status='processed'"
        )
        parameters: tuple[object, ...] = ()
        if session_id is not None:
            sql += " AND session_id=?"
            parameters = (session_id,)
        sql += " ORDER BY result_rowid,pair_id"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["receipt"] = _decode_json(item.pop("receipt_json"))
            receipt_sha256 = item["receipt"].get("receipt_sha256")
            if (
                not isinstance(receipt_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt_sha256)
            ):
                raise ValueError("stored offload sync receipt digest is invalid")
            item["receipt_sha256"] = receipt_sha256
            result.append(item)
        return result

    def list_offload_evidence_refs(
        self, *, session_id: str, limit: int = 10_000
    ) -> list[str]:
        """List opaque refs for explicit audit/drill-down, never raw prose."""

        if not session_id or limit < 1 or limit > 10_000:
            raise ValueError("invalid offload evidence reference query")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT evidence_ref FROM offload_evidence WHERE session_id=? "
                "ORDER BY created_at,evidence_ref LIMIT ?",
                (session_id, limit),
            ).fetchall()
        return [str(row["evidence_ref"]) for row in rows]

    def list_offload_sync_dead_letters(
        self, *, session_id: str | None = None
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM offload_sync_dead_letters"
        parameters: tuple[object, ...] = ()
        if session_id is not None:
            sql += " WHERE session_id=?"
            parameters = (session_id,)
        sql += " ORDER BY rowid"
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]

    def offload_sync_status(self, session_id: str) -> dict[str, Any]:
        with self._connect() as connection:
            state = connection.execute(
                "SELECT cursor_rowid,updated_at FROM offload_sync_state WHERE session_id=?",
                (session_id,),
            ).fetchone()
            counts = connection.execute(
                "SELECT "
                "SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),"
                "SUM(CASE WHEN status='processed' THEN 1 ELSE 0 END),"
                "SUM(CASE WHEN status='dead' THEN 1 ELSE 0 END) "
                "FROM offload_pair_queue WHERE session_id=?",
                (session_id,),
            ).fetchone()
            pending_calls = connection.execute(
                "SELECT COUNT(*) FROM offload_pending_calls WHERE session_id=?",
                (session_id,),
            ).fetchone()[0]
            cursor_rowid = int(state["cursor_rowid"]) if state is not None else 0
            lag_rows = connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE session_id=? AND rowid>? "
                "AND evidence_type IN ('tool_call','tool_result')",
                (session_id, cursor_rowid),
            ).fetchone()[0]
            dlq_count = connection.execute(
                "SELECT COUNT(*) FROM offload_sync_dead_letters WHERE session_id=?",
                (session_id,),
            ).fetchone()[0]
            last_success = connection.execute(
                "SELECT MAX(updated_at) FROM offload_pair_queue "
                "WHERE session_id=? AND status='processed'",
                (session_id,),
            ).fetchone()[0]
        return {
            "session_id": session_id,
            "cursor_rowid": cursor_rowid,
            "updated_at": str(state["updated_at"]) if state is not None else None,
            "last_success_at": str(last_success) if last_success is not None else None,
            "lag_rows": int(lag_rows),
            "pending_calls": int(pending_calls),
            "pending_pairs": int(counts[0] or 0),
            "retry_pairs": int(counts[0] or 0),
            "processed_pairs": int(counts[1] or 0),
            "dead_pairs": int(counts[2] or 0),
            "dlq_count": int(dlq_count),
        }

    @staticmethod
    def _evidence_dict(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["metadata"] = _decode_json(item.pop("metadata_json"))
        return item

    @staticmethod
    def _insert_offload_sync_dead_letter(
        connection: sqlite3.Connection,
        *,
        session_id: str,
        event_id: str,
        error_code: str,
        created_at: str,
    ) -> None:
        dead_letter_id = stable_id("offload-sync-dead", session_id, event_id, error_code)
        connection.execute(
            "INSERT OR IGNORE INTO offload_sync_dead_letters("
            "dead_letter_id,session_id,event_id,error_code,created_at) VALUES(?,?,?,?,?)",
            (dead_letter_id, session_id, event_id, error_code, created_at),
        )

    def _redacted_capture_record(
        self, record: Mapping[str, Any]
    ) -> dict[str, Any]:
        safe = dict(record)
        retained_content = _redact_persisted_text(
            str(record["content"]), self.redaction_policy
        )
        safe["content"] = retained_content
        safe["content_hash"] = hashlib.sha256(
            retained_content.encode("utf-8")
        ).hexdigest()
        safe["metadata"] = redact_value(
            record.get("metadata", {}), self.redaction_policy
        )
        return safe

    @staticmethod
    def _replay_identity_digest(session_id: str, identity_key: str) -> str:
        return hashlib.sha256(
            ("capture-replay\x00" + session_id + "\x00" + identity_key).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _session_digest(session_id: str) -> str:
        return hashlib.sha256(("capture-session\x00" + session_id).encode("utf-8")).hexdigest()

    def _require_session_capture_allowed_tx(
        self, connection: sqlite3.Connection, session_id: str
    ) -> None:
        blocked = connection.execute(
            "SELECT 1 FROM retention_session_tombstones WHERE session_digest=?",
            (self._session_digest(session_id),),
        ).fetchone()
        if blocked is not None:
            raise RetentionPurgeError(
                "purged session is permanently closed to evidence capture"
            )

    def _blocked_replay_identities_tx(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        identity_keys: Sequence[str],
        now: str,
        *,
        cleanup: bool = True,
    ) -> set[str]:
        digests = {
            self._replay_identity_digest(session_id, identity_key): identity_key
            for identity_key in identity_keys
        }
        blocked: set[str] = set()
        digest_keys = list(digests)
        for offset in range(0, len(digest_keys), 500):
            batch = digest_keys[offset : offset + 500]
            if not batch:
                continue
            placeholders = ",".join("?" for _ in batch)
            rows = connection.execute(
                "SELECT identity_digest FROM retention_replay_tombstones "
                f"WHERE identity_digest IN ({placeholders})",
                batch,
            ).fetchall()
            blocked.update(digests[str(row["identity_digest"])] for row in rows)
        return blocked

    def _replay_identity_blocked_tx(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        identity_key: str,
        now: str,
    ) -> bool:
        return identity_key in self._blocked_replay_identities_tx(
            connection, session_id, (identity_key,), now
        )

    def _ensure_evidence_quota(
        self,
        connection: sqlite3.Connection,
        session_id: str,
        *,
        incoming_count: int,
        incoming_bytes: int,
    ) -> None:
        if incoming_count < 0 or incoming_bytes < 0:
            raise ValueError("incoming evidence quota measurements are invalid")
        if incoming_count == 0:
            return
        policy = self.retention_policy
        rows = {
            str(row["session_id"]): (int(row["item_count"]), int(row["retained_bytes"]))
            for row in connection.execute(
                "SELECT session_id,item_count,retained_bytes FROM retention_usage "
                "WHERE storage_class='evidence' AND session_id IN ('',?)",
                (session_id,),
            )
        }
        session = rows.get(session_id, (0, 0))
        global_row = rows.get("", (0, 0))
        checks = (
            (
                session[0] + incoming_count,
                policy.evidence_max_count_per_session,
                "per_session_count",
            ),
            (
                session[1] + incoming_bytes,
                policy.evidence_max_bytes_per_session,
                "per_session_bytes",
            ),
            (
                global_row[0] + incoming_count,
                policy.evidence_max_count_global,
                "global_count",
            ),
            (
                global_row[1] + incoming_bytes,
                policy.evidence_max_bytes_global,
                "global_bytes",
            ),
        )
        exceeded = [name for actual, limit, name in checks if actual > limit]
        if exceeded:
            raise RetentionQuotaExceeded(
                "evidence retention quota exceeded: " + ",".join(exceeded)
            )

    def save_candidate_batch(
        self,
        candidates: Sequence[Mapping[str, Any]],
        relations: Sequence[Mapping[str, Any]],
        *,
        completed_job_id: str | None = None,
        stage_cursor: str | None = None,
        updated_at: str | None = None,
    ) -> tuple[int, int]:
        stamp = updated_at or utc_now()
        created_candidates = 0
        created_relations = 0
        with self._transaction() as connection:
            for candidate in candidates:
                safe_candidate = dict(candidate)
                for field in ("claim", "normalized_claim", "slot_key", "source_span"):
                    safe_candidate[field] = redact_text(
                        str(candidate[field]), self.redaction_policy
                    )
                if safe_candidate["claim"] != candidate["claim"]:
                    safe_candidate["claim_hash"] = hashlib.sha256(
                        str(safe_candidate["claim"]).encode("utf-8")
                    ).hexdigest()
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO candidates(
                        candidate_id,session_id,memory_class,claim,normalized_claim,claim_hash,
                        slot_key,status,requires_authorization,high_impact,expires_at,
                        source_event_id,source_path,source_line,source_span,span_start,span_end,
                        source_text_hash,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        safe_candidate["candidate_id"], safe_candidate["session_id"], safe_candidate["memory_class"],
                        safe_candidate["claim"], safe_candidate["normalized_claim"], safe_candidate["claim_hash"],
                        safe_candidate["slot_key"], safe_candidate["status"], int(safe_candidate["requires_authorization"]),
                        int(safe_candidate["high_impact"]), safe_candidate.get("expires_at"),
                        safe_candidate["source_event_id"], safe_candidate["source_path"], safe_candidate["source_line"],
                        safe_candidate["source_span"], safe_candidate["span_start"], safe_candidate["span_end"],
                        safe_candidate["source_text_hash"], safe_candidate.get("created_at", stamp),
                    ),
                )
                created_candidates += cursor.rowcount
            for relation in relations:
                safe_reason = redact_text(str(relation["reason"]), self.redaction_policy)
                cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO candidate_relations(
                        relation_id,session_id,source_candidate_id,target_candidate_id,
                        relation_type,reason,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        relation["relation_id"], relation["session_id"],
                        relation["source_candidate_id"], relation["target_candidate_id"],
                        relation["relation_type"], safe_reason,
                        relation.get("created_at", stamp),
                    ),
                )
                created_relations += cursor.rowcount
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at) VALUES('distill',?,'ok',?)
                ON CONFLICT(stage) DO UPDATE SET cursor=excluded.cursor,status='ok',updated_at=excluded.updated_at
                """,
                (stage_cursor, stamp),
            )
            if completed_job_id is not None:
                # Capture and proposal formation use separate transactions, but
                # the durable work item is acknowledged in the same transaction
                # as the candidate batch it justified.  A crash before this
                # point leaves a retryable pending job; a crash after it cannot
                # produce a false backlog.  The identity is exact: completing
                # checkpoint N can never acknowledge N+1 from the same session.
                job = connection.execute(
                    "SELECT payload_json FROM jobs WHERE job_id=? AND kind='distill' AND status='pending'",
                    (completed_job_id,),
                ).fetchone()
                if job is None:
                    raise ValueError("distill job is not pending")
                payload = _decode_json(job["payload_json"])
                if not isinstance(payload, dict) or not isinstance(payload.get("session_id"), str):
                    raise ValueError("distill job payload is invalid")
                connection.execute(
                    """
                    UPDATE jobs SET status='succeeded',result_json=?,lease_owner=NULL,lease_until=NULL,
                        error_code=NULL,error_detail=NULL,updated_at=? WHERE job_id=? AND status='pending'
                    """,
                    (
                        canonical_json(
                            {
                                "session_id": payload["session_id"],
                                "checkpoint_line": payload.get("checkpoint_line"),
                                "candidates_created": created_candidates,
                                "relations_created": created_relations,
                            }
                        ),
                        stamp,
                        completed_job_id,
                    ),
                )
        return created_candidates, created_relations

    def list_candidates(self, session_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM candidates"
        parameters: tuple[object, ...] = ()
        if session_id is not None:
            sql += " WHERE session_id=?"
            parameters = (session_id,)
        sql += " ORDER BY rowid"
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["requires_authorization"] = bool(item["requires_authorization"])
            item["high_impact"] = bool(item["high_impact"])
            result.append(item)
        return result

    def list_relations(self, session_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM candidate_relations"
        parameters: tuple[object, ...] = ()
        if session_id is not None:
            sql += " WHERE session_id=?"
            parameters = (session_id,)
        sql += " ORDER BY rowid"
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(sql, parameters).fetchall()]

    def enqueue_job(
        self,
        kind: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        *,
        max_attempts: int = 3,
        now: str | None = None,
    ) -> dict[str, Any]:
        if not kind or not idempotency_key or max_attempts < 1:
            raise ValueError("invalid durable job")
        stamp = now or utc_now()
        job_id = stable_id("job", kind, idempotency_key)
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO jobs(
                    job_id,kind,idempotency_key,payload_json,status,attempts,max_attempts,
                    available_at,created_at,updated_at
                ) VALUES(?,?,?,?, 'pending',0,?,?,?,?)
                """,
                (
                    job_id,
                    kind,
                    idempotency_key,
                    canonical_json(redact_value(payload, self.redaction_policy)),
                    max_attempts,
                    stamp,
                    stamp,
                    stamp,
                ),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        assert row is not None
        return self._job_dict(row)

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM jobs ORDER BY rowid").fetchall()
        return [self._job_dict(row) for row in rows]

    def lease_jobs(
        self,
        worker_id: str,
        *,
        now: str,
        lease_until: str,
        kinds: Sequence[str] | None = None,
        limit: int = 1,
    ) -> list[dict[str, Any]]:
        if not worker_id or limit < 1:
            raise ValueError("invalid lease request")
        with self._transaction() as connection:
            parameters: list[object] = [now]
            sql = "SELECT job_id FROM jobs WHERE status='pending' AND available_at<=?"
            if kinds:
                sql += " AND kind IN ({})".format(",".join("?" for _ in kinds))
                parameters.extend(kinds)
            sql += " ORDER BY available_at,created_at,job_id LIMIT ?"
            parameters.append(limit)
            ids = [row["job_id"] for row in connection.execute(sql, parameters).fetchall()]
            for job_id in ids:
                connection.execute(
                    """
                    UPDATE jobs SET status='leased',attempts=attempts+1,lease_owner=?,lease_until=?,updated_at=?
                    WHERE job_id=? AND status='pending'
                    """,
                    (worker_id, lease_until, now, job_id),
                )
            rows = [connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone() for job_id in ids]
        return [self._job_dict(row) for row in rows if row is not None]

    def complete_job(
        self, job_id: str, worker_id: str, result: Mapping[str, Any], *, now: str
    ) -> dict[str, Any] | None:
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE jobs SET status='succeeded',result_json=?,lease_owner=NULL,lease_until=NULL,
                    error_code=NULL,error_detail=NULL,updated_at=?
                WHERE job_id=? AND status='leased' AND lease_owner=?
                """,
                (
                    canonical_json(redact_value(result, self.redaction_policy)),
                    now,
                    job_id,
                    worker_id,
                ),
            )
            if cursor.rowcount != 1:
                return None
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._job_dict(row)

    def fail_job(
        self,
        job_id: str,
        worker_id: str,
        error_code: str,
        error_detail: str,
        *,
        now: str,
        retry_at: str,
    ) -> dict[str, Any] | None:
        error_detail = redact_text(error_detail, self.redaction_policy)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM jobs WHERE job_id=? AND status='leased' AND lease_owner=?",
                (job_id, worker_id),
            ).fetchone()
            if row is None:
                return None
            dead = row["attempts"] >= row["max_attempts"]
            status = "dead" if dead else "pending"
            connection.execute(
                """
                UPDATE jobs SET status=?,available_at=?,lease_owner=NULL,lease_until=NULL,
                    error_code=?,error_detail=?,updated_at=? WHERE job_id=?
                """,
                (status, retry_at, error_code, error_detail, now, job_id),
            )
            if dead:
                self._insert_dead_letter(connection, row, error_code, error_detail, now)
            updated = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._job_dict(updated)

    def recover_expired_jobs(self, *, now: str) -> tuple[int, int]:
        requeued = 0
        dead_lettered = 0
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs WHERE status='leased' AND lease_until<=? ORDER BY lease_until",
                (now,),
            ).fetchall()
            for row in rows:
                if row["attempts"] >= row["max_attempts"]:
                    connection.execute(
                        """
                        UPDATE jobs SET status='dead',lease_owner=NULL,lease_until=NULL,
                            error_code='lease_expired',error_detail='worker lease expired',updated_at=?
                        WHERE job_id=?
                        """,
                        (now, row["job_id"]),
                    )
                    self._insert_dead_letter(
                        connection, row, "lease_expired", "worker lease expired", now
                    )
                    dead_lettered += 1
                else:
                    connection.execute(
                        """
                        UPDATE jobs SET status='pending',available_at=?,lease_owner=NULL,lease_until=NULL,
                            error_code='lease_expired',error_detail='worker lease expired',updated_at=?
                        WHERE job_id=?
                        """,
                        (now, now, row["job_id"]),
                    )
                    requeued += 1
        return requeued, dead_lettered

    def list_dead_letters(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM dead_letters ORDER BY rowid").fetchall()]

    def heartbeat(self, stage: str, cursor: str | None, status: str, *, now: str) -> None:
        if not stage:
            raise ValueError("stage is required")
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at) VALUES(?,?,?,?)
                ON CONFLICT(stage) DO UPDATE SET cursor=excluded.cursor,status=excluded.status,updated_at=excluded.updated_at
                """,
                (stage, cursor, status, now),
            )

    def record_pipeline_error(
        self,
        stage: str,
        error_code: str,
        detail: str,
        source_ref: str | None = None,
        *,
        now: str | None = None,
    ) -> str:
        stamp = now or utc_now()
        _parse_timestamp(stamp)
        policy = self.retention_policy
        stage = _truncate_utf8(redact_text(stage, self.redaction_policy), 128)
        error_code = _truncate_utf8(redact_text(error_code, self.redaction_policy), 128)
        if not stage or not error_code:
            raise ValueError("pipeline error stage and code are required")
        detail = _truncate_utf8(
            redact_text(detail, self.redaction_policy),
            policy.pipeline_error_detail_max_bytes,
        )
        source_ref = (
            _truncate_utf8(redact_text(source_ref, self.redaction_policy), 512)
            if source_ref is not None
            else None
        )
        fingerprint = stable_id("error-fingerprint", stage, error_code, source_ref or "", detail)
        error_id = stable_id("error", fingerprint)
        with self._transaction() as connection:
            self._prune_pipeline_errors_tx(connection, now=stamp)
            existing = connection.execute(
                "SELECT error_id FROM pipeline_errors WHERE fingerprint=? "
                "ORDER BY occurred_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if existing is not None:
                error_id = str(existing["error_id"])
                connection.execute(
                    "UPDATE pipeline_errors SET occurrence_count=occurrence_count+1,"
                    "occurred_at=? WHERE error_id=?",
                    (stamp, error_id),
                )
            else:
                window_start = _timestamp_before(
                    stamp, policy.pipeline_error_rate_window_seconds
                )
                recent_unique = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM pipeline_errors "
                        "WHERE occurred_at>? AND rate_limited=0",
                        (window_start,),
                    ).fetchone()[0]
                )
                rate_limited = recent_unique >= policy.pipeline_error_rate_max_unique
                if rate_limited:
                    error_code = "pipeline_error_rate_limited"
                    detail = "additional unique pipeline errors coalesced"
                    source_ref = None
                    fingerprint = stable_id("error-fingerprint", stage, error_code)
                    error_id = stable_id("error", fingerprint)
                    limited = connection.execute(
                        "SELECT error_id FROM pipeline_errors WHERE fingerprint=? LIMIT 1",
                        (fingerprint,),
                    ).fetchone()
                    if limited is not None:
                        error_id = str(limited["error_id"])
                        connection.execute(
                            "UPDATE pipeline_errors SET occurrence_count=occurrence_count+1,"
                            "occurred_at=? WHERE error_id=?",
                            (stamp, error_id),
                        )
                    else:
                        self._insert_pipeline_error_tx(
                            connection, error_id, fingerprint, stage, error_code,
                            detail, source_ref, stamp, rate_limited=True,
                        )
                else:
                    self._insert_pipeline_error_tx(
                        connection, error_id, fingerprint, stage, error_code,
                        detail, source_ref, stamp, rate_limited=False,
                    )
            self._prune_pipeline_errors_tx(connection, now=stamp)
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at) VALUES(?,?,'error',?)
                ON CONFLICT(stage) DO UPDATE SET cursor=excluded.cursor,status='error',updated_at=excluded.updated_at
                """,
                (stage, source_ref, stamp),
            )
        return error_id

    def _insert_pipeline_error_tx(
        self,
        connection: sqlite3.Connection,
        error_id: str,
        fingerprint: str,
        stage: str,
        error_code: str,
        detail: str,
        source_ref: str | None,
        stamp: str,
        *,
        rate_limited: bool,
    ) -> None:
        retained_bytes = len(detail.encode("utf-8")) + len((source_ref or "").encode("utf-8"))
        connection.execute(
            "INSERT INTO pipeline_errors("
            "error_id,stage,error_code,detail,source_ref,occurred_at,fingerprint,"
            "occurrence_count,first_occurred_at,retained_bytes,rate_limited) "
            "VALUES(?,?,?,?,?,?,?,1,?,?,?)",
            (
                error_id, stage, error_code, detail, source_ref, stamp, fingerprint,
                stamp, retained_bytes, int(rate_limited),
            ),
        )

    def _prune_pipeline_errors_tx(
        self, connection: sqlite3.Connection, *, now: str
    ) -> None:
        policy = self.retention_policy
        cutoff = _timestamp_before(now, policy.pipeline_error_ttl_seconds)
        connection.execute("DELETE FROM pipeline_errors WHERE occurred_at<=?", (cutoff,))
        connection.execute(
            "DELETE FROM pipeline_errors WHERE error_id NOT IN ("
            "SELECT error_id FROM pipeline_errors ORDER BY occurred_at DESC,error_id DESC LIMIT ?)",
            (policy.pipeline_error_max_count,),
        )
        while True:
            row = connection.execute(
                "SELECT COUNT(*),COALESCE(SUM(retained_bytes),0) FROM pipeline_errors"
            ).fetchone()
            if int(row[0]) == 0 or int(row[1]) <= policy.pipeline_error_max_bytes:
                break
            connection.execute(
                "DELETE FROM pipeline_errors WHERE error_id=(SELECT error_id FROM pipeline_errors "
                "ORDER BY occurred_at,error_id LIMIT 1)"
            )

    def purge_session(
        self,
        session_id: str,
        *,
        now: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Delete one session's private evidence and every store-owned projection.

        Replay identities and capture checkpoints are retained as opaque
        tombstones.  This prevents a normal hook retry or transcript resume from
        silently recreating evidence that was explicitly purged.
        """

        if not session_id or "\x00" in session_id:
            raise ValueError("invalid purge session")
        _parse_timestamp(now)
        targets = {
            "all_sessions": {session_id},
            "derivative_sessions": {session_id},
            "event_ids": set(),
            "candidate_ids": set(),
            "offload_refs": set(),
            "task_keys": set(),
        }
        selector_digest = hashlib.sha256(
            ("session\x1f" + session_id).encode("utf-8")
        ).hexdigest()
        return self._execute_purge(
            targets,
            now=now,
            reason="manual",
            selector_digest=selector_digest,
            request_id=request_id,
        )

    @staticmethod
    def _authority_purge_request_id(authority_receipt_id: str) -> str:
        if not authority_receipt_id or "\x00" in authority_receipt_id:
            raise ValueError("invalid authority receipt id")
        return "authority\x1f" + authority_receipt_id

    def get_authority_purge_receipt(
        self, authority_receipt_id: str
    ) -> dict[str, Any] | None:
        """Reopen a sanitized runtime receipt without reopening deleted data."""

        request_source = self._authority_purge_request_id(authority_receipt_id)
        request_key = hashlib.sha256(request_source.encode("utf-8")).hexdigest()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT status,receipt_json FROM retention_purge_receipts "
                "WHERE request_id=? AND reason='authority'",
                (request_key,),
            ).fetchone()
            if row is not None and row["status"] == "applied":
                return json.loads(str(row["receipt_json"]))
            authority_digest = hashlib.sha256(
                authority_receipt_id.encode("utf-8")
            ).hexdigest()
            binding = connection.execute(
                "SELECT * FROM retention_authority_purge_bindings "
                "WHERE authority_receipt_digest=?",
                (authority_digest,),
            ).fetchone()
        if binding is None:
            return None
        return {
            "schema_version": 1,
            "receipt_id": str(binding["purge_receipt_id"]),
            "status": "applied",
            "reason": "authority",
            "selector_digest": str(binding["selector_digest"]),
            "authority_receipt_digest": authority_digest,
            "applied_at": str(binding["applied_at"]),
        }

    def purge_authority_sessions(
        self,
        session_ids: Sequence[str],
        *,
        authority_receipt_id: str,
        now: str,
    ) -> dict[str, Any]:
        """Atomically purge all runtime sessions bound to one authority receipt."""

        _parse_timestamp(now)
        sessions = {str(session_id) for session_id in session_ids}
        if not sessions or "" in sessions or any("\x00" in item for item in sessions):
            raise ValueError("invalid authority purge sessions")
        request_source = self._authority_purge_request_id(authority_receipt_id)
        session_digests = sorted(
            hashlib.sha256(session.encode("utf-8")).hexdigest()
            for session in sessions
        )
        selector_digest = hashlib.sha256(
            canonical_json(session_digests).encode("utf-8")
        ).hexdigest()
        targets = {
            "all_sessions": sessions,
            "derivative_sessions": sessions,
            "event_ids": set(),
            "candidate_ids": set(),
            "offload_refs": set(),
            "task_keys": set(),
        }
        return self._execute_purge(
            targets,
            now=now,
            reason="authority",
            selector_digest=selector_digest,
            request_id=request_source,
            receipt_fields={
                "authority_receipt_digest": hashlib.sha256(
                    authority_receipt_id.encode("utf-8")
                ).hexdigest(),
                "session_selector_digests": session_digests,
            },
        )

    def run_retention_gc(
        self,
        *,
        now: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Apply one durable, globally bounded retention batch."""

        _parse_timestamp(now)
        policy = self.retention_policy
        cutoffs = {
            "evidence": _timestamp_before(now, policy.evidence_ttl_seconds),
            "candidate": _timestamp_before(now, policy.candidate_ttl_seconds),
            "offload": _timestamp_before(now, policy.offload_ttl_seconds),
        }
        selected: list[tuple[str, str]] = []
        has_more = False
        with self._transaction() as connection:
            self._prune_pipeline_errors_tx(connection, now=now)
            queries = (
                (
                    "event",
                    "SELECT event_id AS item_key,session_id FROM evidence WHERE captured_at<=? "
                    "ORDER BY captured_at,event_id LIMIT ?",
                    cutoffs["evidence"],
                ),
                (
                    "candidate",
                    "SELECT candidate_id AS item_key,NULL AS session_id FROM candidates "
                    "WHERE created_at<=? ORDER BY created_at,candidate_id LIMIT ?",
                    cutoffs["candidate"],
                ),
                (
                    "offload",
                    "SELECT evidence_ref AS item_key,NULL AS session_id FROM offload_evidence "
                    "WHERE created_at<=? ORDER BY created_at,evidence_ref LIMIT ?",
                    cutoffs["offload"],
                ),
                (
                    "task",
                    "SELECT task_id || ':' || version AS item_key,NULL AS session_id "
                    "FROM offload_tasks WHERE created_at<=? "
                    "ORDER BY created_at,task_id,version LIMIT ?",
                    cutoffs["offload"],
                ),
            )
            for kind, sql, cutoff in queries:
                remaining = policy.gc_batch_size - len(selected)
                if remaining <= 0:
                    has_more = True
                    break
                rows = connection.execute(sql, (cutoff, remaining + 1)).fetchall()
                if len(rows) > remaining:
                    has_more = True
                for row in rows[:remaining]:
                    key = str(row["item_key"])
                    selected.append((kind, key))

            remaining = policy.gc_batch_size - len(selected)
            if remaining > 0:
                version_rows = connection.execute(
                    "SELECT task_id || ':' || version AS item_key FROM ("
                    "SELECT task_id,version,ROW_NUMBER() OVER (PARTITION BY task_id "
                    "ORDER BY version DESC) AS version_rank FROM offload_tasks) "
                    "WHERE version_rank>? ORDER BY item_key LIMIT ?",
                    (policy.task_versions_max_per_task, remaining + 1),
                ).fetchall()
                if len(version_rows) > remaining:
                    has_more = True
                selected.extend(
                    ("task", str(row["item_key"]))
                    for row in version_rows[:remaining]
                    if ("task", str(row["item_key"])) not in selected
                )

        event_ids = {key for kind, key in selected if kind == "event"}
        targets = {
            "all_sessions": set(),
            # TTL of one evidence row must not fan out into an unbounded session
            # purge. Candidate dependencies are selected by event_id below; all
            # other private copies have their own independently bounded TTL.
            "derivative_sessions": set(),
            "event_ids": event_ids,
            "candidate_ids": {key for kind, key in selected if kind == "candidate"},
            "offload_refs": {key for kind, key in selected if kind == "offload"},
            "task_keys": {key for kind, key in selected if kind == "task"},
        }
        selector_digest = hashlib.sha256(
            canonical_json(
                {
                    key: sorted(str(item) for item in value)
                    for key, value in targets.items()
                }
            ).encode("utf-8")
        ).hexdigest()
        cursor = f"{selected[-1][0]}:{selected[-1][1]}" if selected else None
        gc_fields = {
            "gc": {
                "selected_count": len(selected),
                "batch_size": policy.gc_batch_size,
                "cursor": cursor,
                "has_more": has_more,
            }
        }
        receipt = self._execute_purge(
            targets,
            now=now,
            reason="ttl",
            selector_digest=selector_digest,
            request_id=request_id,
            receipt_fields=gc_fields,
        )
        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO retention_gc_state("
                "singleton,last_run_at,last_success_at,cursor,has_more,status,last_receipt_id) "
                "VALUES(1,?,?,?,?, 'ok',?) ON CONFLICT(singleton) DO UPDATE SET "
                "last_run_at=excluded.last_run_at,last_success_at=excluded.last_success_at,"
                "cursor=excluded.cursor,has_more=excluded.has_more,status='ok',"
                "last_receipt_id=excluded.last_receipt_id",
                (now, now, cursor, int(has_more), receipt["receipt_id"]),
            )
        return receipt

    def list_purge_receipts(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT receipt_json FROM retention_purge_receipts "
                "ORDER BY created_at,receipt_id"
            ).fetchall()
        return [json.loads(str(row["receipt_json"])) for row in rows]

    @staticmethod
    def _quota_overflow_keys(
        rows: Sequence[Mapping[str, Any]],
        *,
        key_name: str,
        session_name: str,
        per_session_count: int,
        per_session_bytes: int,
        global_count: int,
        global_bytes: int,
    ) -> set[str]:
        """Return oldest keys that cannot fit while retaining newest rows."""

        overflow: set[str] = set()

        def mark(group: Sequence[Mapping[str, Any]], count_limit: int, byte_limit: int) -> None:
            kept_count = 0
            kept_bytes = 0
            for row in reversed(group):
                size = int(row.get("retained_bytes") or 0)
                if kept_count + 1 <= count_limit and kept_bytes + size <= byte_limit:
                    kept_count += 1
                    kept_bytes += size
                else:
                    overflow.add(str(row[key_name]))

        sessions: dict[str, list[Mapping[str, Any]]] = {}
        for row in rows:
            sessions.setdefault(str(row.get(session_name) or ""), []).append(row)
        for group in sessions.values():
            mark(group, per_session_count, per_session_bytes)
        mark(rows, global_count, global_bytes)
        return overflow

    def _execute_purge(
        self,
        targets: Mapping[str, set[str]],
        *,
        now: str,
        reason: str,
        selector_digest: str,
        request_id: str | None,
        receipt_fields: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        request_source = request_id or stable_id(
            "purge-request", reason, selector_digest, now
        )
        request_key = hashlib.sha256(request_source.encode("utf-8")).hexdigest()
        receipt_id = stable_id("purge", request_key)
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT status,receipt_json FROM retention_purge_receipts WHERE request_id=?",
                (request_key,),
            ).fetchone()
        if existing is not None and existing["status"] == "applied":
            receipt = json.loads(str(existing["receipt_json"]))
            if receipt.get("physical_status") != "applied":
                try:
                    self._finalize_physical_purge()
                except Exception as error:
                    raise RetentionPurgeError(
                        "logical purge is applied; physical cleanup remains pending"
                    ) from error
                receipt["physical_status"] = "applied"
                receipt["physically_purged_at"] = now
                with self._transaction() as connection:
                    connection.execute(
                        "UPDATE retention_purge_receipts SET receipt_json=?,updated_at=? "
                        "WHERE request_id=? AND status='applied'",
                        (canonical_json(receipt), now, request_key),
                    )
            return receipt
        try:
            with self._transaction() as connection:
                deleted = self._purge_targets_tx(
                    connection,
                    targets,
                    purge_receipt_id=receipt_id,
                    now=now,
                )
                receipt_cutoff = _timestamp_before(
                    now, self.retention_policy.receipt_ttl_seconds
                )
                deleted["restore_tombstones"] = 0
                deleted["replay_tombstones"] = 0
                old_receipts = connection.execute(
                    "DELETE FROM retention_purge_receipts WHERE updated_at<=? AND request_id!=?",
                    (receipt_cutoff, request_key),
                ).rowcount
                deleted["purge_receipts"] = old_receipts
                receipt = {
                    "schema_version": 1,
                    "receipt_id": receipt_id,
                    "status": "applied",
                    "physical_status": "pending",
                    "reason": reason,
                    "selector_digest": selector_digest,
                    "policy_digest": self._policy_digest(),
                    "deleted": deleted,
                    "applied_at": now,
                }
                if receipt_fields:
                    receipt.update(receipt_fields)
                if reason == "authority" and receipt_fields:
                    authority_digest = receipt_fields.get("authority_receipt_digest")
                    if isinstance(authority_digest, str):
                        connection.execute(
                            "INSERT INTO retention_authority_purge_bindings("
                            "authority_receipt_digest,purge_receipt_id,selector_digest,applied_at) "
                            "VALUES(?,?,?,?) ON CONFLICT(authority_receipt_digest) DO UPDATE SET "
                            "purge_receipt_id=excluded.purge_receipt_id,"
                            "selector_digest=excluded.selector_digest,applied_at=excluded.applied_at",
                            (authority_digest, receipt_id, selector_digest, now),
                        )
                connection.execute(
                    """
                    INSERT INTO retention_purge_receipts(
                        receipt_id,request_id,status,reason,selector_digest,
                        receipt_json,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    ON CONFLICT(request_id) DO UPDATE SET
                        status='applied',reason=excluded.reason,
                        selector_digest=excluded.selector_digest,
                        receipt_json=excluded.receipt_json,updated_at=excluded.updated_at
                    """,
                    (
                        receipt_id,
                        request_key,
                        "applied",
                        reason,
                        selector_digest,
                        canonical_json(receipt),
                        now,
                        now,
                    ),
                )
        except Exception as error:
            failure = {
                "schema_version": 1,
                "receipt_id": receipt_id,
                "status": "failed",
                "reason": reason,
                "selector_digest": selector_digest,
                "policy_digest": self._policy_digest(),
                "error_code": "purge_failed",
                "failure_digest": hashlib.sha256(
                    redact_text(str(error), self.redaction_policy).encode("utf-8")
                ).hexdigest(),
                "failed_at": now,
            }
            if receipt_fields:
                failure.update(receipt_fields)
            try:
                with self._transaction() as connection:
                    if reason == "authority" and receipt_fields:
                        authority_digest = receipt_fields.get("authority_receipt_digest")
                        if isinstance(authority_digest, str):
                            connection.execute(
                                "DELETE FROM retention_authority_purge_bindings "
                                "WHERE authority_receipt_digest=?",
                                (authority_digest,),
                            )
                    connection.execute(
                        """
                        INSERT INTO retention_purge_receipts(
                            receipt_id,request_id,status,reason,selector_digest,
                            receipt_json,created_at,updated_at
                        ) VALUES(?,?,?,?,?,?,?,?)
                        ON CONFLICT(request_id) DO UPDATE SET
                            status='failed',reason=excluded.reason,
                            selector_digest=excluded.selector_digest,
                            receipt_json=excluded.receipt_json,updated_at=excluded.updated_at
                        """,
                        (
                            receipt_id,
                            request_key,
                            "failed",
                            reason,
                            selector_digest,
                            canonical_json(failure),
                            now,
                            now,
                        ),
                    )
            except Exception:
                pass
            raise RetentionPurgeError(
                "retention purge failed atomically; retry the same request id"
            ) from error
        try:
            self._finalize_physical_purge()
        except Exception as error:
            raise RetentionPurgeError(
                "logical purge is applied; physical cleanup remains pending"
            ) from error
        receipt["physical_status"] = "applied"
        receipt["physically_purged_at"] = now
        with self._transaction() as connection:
            connection.execute(
                "UPDATE retention_purge_receipts SET receipt_json=?,updated_at=? "
                "WHERE request_id=? AND status='applied'",
                (canonical_json(receipt), now, request_key),
            )
        return receipt

    def _purge_targets_tx(
        self,
        connection: sqlite3.Connection,
        targets: Mapping[str, set[str]],
        *,
        purge_receipt_id: str,
        now: str,
    ) -> dict[str, int]:
        all_sessions = set(targets.get("all_sessions", set()))
        derivative_sessions = set(targets.get("derivative_sessions", set()))
        event_ids = set(targets.get("event_ids", set()))
        candidate_ids = set(targets.get("candidate_ids", set()))
        if all_sessions:
            candidate_ids.update(
                str(row["candidate_id"])
                for row in connection.execute("SELECT candidate_id,session_id FROM candidates")
                if str(row["session_id"]) in all_sessions
            )
            event_ids.update(
                str(row["event_id"])
                for row in connection.execute("SELECT event_id,session_id FROM evidence")
                if str(row["session_id"]) in all_sessions
            )
        if event_ids:
            for offset in range(0, len(event_ids), 500):
                batch = list(event_ids)[offset : offset + 500]
                placeholders = ",".join("?" for _ in batch)
                candidate_ids.update(
                    str(row["candidate_id"])
                    for row in connection.execute(
                        f"SELECT candidate_id FROM candidates WHERE source_event_id IN ({placeholders})",
                        batch,
                    )
                )

        deleted = {
            "evidence": 0,
            "candidates": 0,
            "relations": 0,
            "offload_evidence": 0,
            "offload_tasks": 0,
            "offload_receipts": 0,
            "offload_sync_state": 0,
            "jobs": 0,
            "dead_letters": 0,
            "pipeline_errors": 0,
            "capture_event_identities": 0,
            "capture_checkpoints": 0,
            "stage_cursors": 0,
        }
        if candidate_ids:
            relation_ids: list[str] = []
            candidate_values = list(candidate_ids)
            for offset in range(0, len(candidate_values), 250):
                batch = candidate_values[offset : offset + 250]
                placeholders = ",".join("?" for _ in batch)
                relation_ids.extend(
                    str(row["relation_id"])
                    for row in connection.execute(
                        "SELECT relation_id FROM candidate_relations WHERE "
                        f"source_candidate_id IN ({placeholders}) OR "
                        f"target_candidate_id IN ({placeholders})",
                        (*batch, *batch),
                    )
                )
            deleted["relations"] = self._delete_keys(
                connection, "candidate_relations", "relation_id", relation_ids
            )
            deleted["candidates"] = self._delete_keys(
                connection, "candidates", "candidate_id", candidate_ids
            )
        if event_ids:
            deleted["evidence"] = self._delete_keys(
                connection, "evidence", "event_id", event_ids
            )

        affected_sessions = all_sessions | derivative_sessions
        if affected_sessions:
            deleted["offload_sync_state"] = self._delete_keys(
                connection,
                "offload_sync_state",
                "session_id",
                affected_sessions,
            )
            job_ids = []
            for row in connection.execute("SELECT job_id,payload_json FROM jobs"):
                payload = _decode_json(str(row["payload_json"]))
                if isinstance(payload, dict) and str(payload.get("session_id") or "") in affected_sessions:
                    job_ids.append(str(row["job_id"]))
            if job_ids:
                dead_letter_ids = [
                    str(row["dead_letter_id"])
                    for row in connection.execute(
                        "SELECT dead_letter_id,job_id FROM dead_letters"
                    )
                    if str(row["job_id"]) in job_ids
                ]
                deleted["dead_letters"] = self._delete_keys(
                    connection,
                    "dead_letters",
                    "dead_letter_id",
                    dead_letter_ids,
                )
            deleted["jobs"] = self._delete_keys(
                connection, "jobs", "job_id", job_ids
            )
            error_ids = [
                str(row["error_id"])
                for row in connection.execute(
                    "SELECT error_id,source_ref FROM pipeline_errors"
                )
                if any(
                    str(row["source_ref"] or "") == "session:" + session
                    or str(row["source_ref"] or "").startswith("session:" + session + ":")
                    for session in affected_sessions
                )
            ]
            deleted["pipeline_errors"] = self._delete_keys(
                connection, "pipeline_errors", "error_id", error_ids
            )
            stage_names = [
                str(row["stage"])
                for row in connection.execute("SELECT stage,cursor FROM stage_state")
                if any(
                    str(row["cursor"] or "") == session
                    or str(row["cursor"] or "").startswith(session + ":")
                    for session in affected_sessions
                )
            ]
            for stage in stage_names:
                deleted["stage_cursors"] += connection.execute(
                    "UPDATE stage_state SET cursor=NULL,status='purged',updated_at=? "
                    "WHERE stage=?",
                    (now, stage),
                ).rowcount

        if all_sessions:
            replay_expiry = "9999-12-31T23:59:59Z"
            for session_id in sorted(all_sessions):
                connection.execute(
                    "INSERT INTO retention_session_tombstones("
                    "session_digest,purge_receipt_id,created_at) VALUES(?,?,?) "
                    "ON CONFLICT(session_digest) DO UPDATE SET "
                    "purge_receipt_id=excluded.purge_receipt_id,created_at=excluded.created_at",
                    (self._session_digest(session_id), purge_receipt_id, now),
                )
                identities = connection.execute(
                    "SELECT identity_key FROM capture_event_identities WHERE session_id=?",
                    (session_id,),
                ).fetchall()
                for row in identities:
                    connection.execute(
                        "INSERT INTO retention_replay_tombstones("
                        "identity_digest,created_at,expires_at) VALUES(?,?,?) "
                        "ON CONFLICT(identity_digest) DO UPDATE SET "
                        "created_at=excluded.created_at,expires_at=excluded.expires_at",
                        (
                            self._replay_identity_digest(
                                session_id, str(row["identity_key"])
                            ),
                            now,
                            replay_expiry,
                        ),
                    )
            deleted["capture_event_identities"] = self._delete_keys(
                connection,
                "capture_event_identities",
                "session_id",
                all_sessions,
            )
            deleted["capture_checkpoints"] = self._delete_keys(
                connection,
                "capture_checkpoints",
                "session_id",
                all_sessions,
            )

        offload_refs = set(targets.get("offload_refs", set()))
        task_ids: set[str] = set()
        task_versions = {
            (str(key).rsplit(":", 1)[0], int(str(key).rsplit(":", 1)[1]))
            for key in targets.get("task_keys", set())
        }
        if affected_sessions:
            session_values = sorted(affected_sessions)
            for offset in range(0, len(session_values), 500):
                batch = session_values[offset : offset + 500]
                placeholders = ",".join("?" for _ in batch)
                task_ids.update(
                    str(row["task_id"])
                    for row in connection.execute(
                        f"SELECT task_id FROM offload_tasks WHERE session_id IN ({placeholders})",
                        batch,
                    )
                )
            # Only explicit whole-session purges need the bounded legacy fallback
            # for pre-session_id task rows. Incremental GC never enters this path.
            if all_sessions:
                for row in connection.execute(
                    "SELECT task_id,snapshot_json FROM offload_tasks WHERE session_id IS NULL"
                ):
                    snapshot = str(row["snapshot_json"])
                    if any(
                        f"session:{session}:" in snapshot
                        or f"codex-session:{session}" in snapshot
                        for session in affected_sessions
                    ):
                        task_ids.add(str(row["task_id"]))
        if task_ids:
            task_values = sorted(task_ids)
            task_rows: list[sqlite3.Row] = []
            receipt_ids: list[str] = []
            for offset in range(0, len(task_values), 500):
                batch = task_values[offset : offset + 500]
                placeholders = ",".join("?" for _ in batch)
                task_rows.extend(
                    connection.execute(
                        f"SELECT task_id,snapshot_json FROM offload_tasks WHERE task_id IN ({placeholders})",
                        batch,
                    ).fetchall()
                )
                receipt_ids.extend(
                    str(row["receipt_id"])
                    for row in connection.execute(
                        f"SELECT receipt_id FROM offload_receipts WHERE task_id IN ({placeholders})",
                        batch,
                    )
                )
            for row in task_rows:
                self._collect_snapshot_evidence_refs(str(row["snapshot_json"]), offload_refs)
            deleted["offload_receipts"] = self._delete_keys(
                connection, "offload_receipts", "receipt_id", receipt_ids
            )
            deleted["offload_tasks"] = self._delete_keys(
                connection, "offload_tasks", "task_id", task_ids
            )
        for task_id, version in sorted(task_versions):
            row = connection.execute(
                "SELECT snapshot_json FROM offload_tasks WHERE task_id=? AND version=?",
                (task_id, version),
            ).fetchone()
            if row is None:
                continue
            deleted["offload_receipts"] += connection.execute(
                "DELETE FROM offload_receipts WHERE task_id=? AND version=?",
                (task_id, version),
            ).rowcount
            deleted["offload_tasks"] += connection.execute(
                "DELETE FROM offload_tasks WHERE task_id=? AND version=?",
                (task_id, version),
            ).rowcount
        if affected_sessions:
            session_values = sorted(affected_sessions)
            for offset in range(0, len(session_values), 500):
                batch = session_values[offset : offset + 500]
                placeholders = ",".join("?" for _ in batch)
                offload_refs.update(
                    str(row["evidence_ref"])
                    for row in connection.execute(
                        f"SELECT evidence_ref FROM offload_evidence WHERE session_id IN ({placeholders})",
                        batch,
                    )
                )
            if all_sessions:
                for row in connection.execute(
                    "SELECT evidence_ref,source_ref FROM offload_evidence WHERE session_id IS NULL"
                ):
                    if any(
                        f"session:{session}:" in str(row["source_ref"] or "")
                        for session in affected_sessions
                    ):
                        offload_refs.add(str(row["evidence_ref"]))
        tombstone_expiry = "9999-12-31T23:59:59Z"
        for evidence_ref in sorted(offload_refs):
            identity_digest = hashlib.sha256(
                ("offload_evidence\x00" + evidence_ref).encode("utf-8")
            ).hexdigest()
            connection.execute(
                "INSERT OR IGNORE INTO retention_restore_tombstones("
                "identity_digest,kind,purge_receipt_id,created_at,expires_at) "
                "VALUES(?,'offload_evidence',?,?,?)",
                (identity_digest, purge_receipt_id, now, tombstone_expiry),
            )
        deleted["offload_evidence"] = self._delete_keys(
            connection, "offload_evidence", "evidence_ref", offload_refs
        )
        return deleted

    @staticmethod
    def _collect_snapshot_evidence_refs(
        snapshot_json: str, output: set[str]
    ) -> None:
        try:
            snapshot = json.loads(snapshot_json)
        except json.JSONDecodeError:
            return
        for step in snapshot.get("steps", []) if isinstance(snapshot, dict) else []:
            if isinstance(step, dict) and isinstance(step.get("evidence_ref"), str):
                output.add(str(step["evidence_ref"]))

    @staticmethod
    def _delete_keys(
        connection: sqlite3.Connection,
        table: str,
        column: str,
        keys: Iterable[str],
    ) -> int:
        values = list(dict.fromkeys(str(key) for key in keys))
        deleted = 0
        for offset in range(0, len(values), 500):
            batch = values[offset : offset + 500]
            if not batch:
                continue
            placeholders = ",".join("?" for _ in batch)
            deleted += connection.execute(
                f"DELETE FROM {table} WHERE {column} IN ({placeholders})", batch
            ).rowcount
        return deleted

    def _policy_digest(self) -> str:
        return hashlib.sha256(
            canonical_json(asdict(self.retention_policy)).encode("utf-8")
        ).hexdigest()

    def health_rows(self, *, now: str, stale_before: str) -> dict[str, Any]:
        with self._connect() as connection:
            stages = [dict(row) for row in connection.execute("SELECT * FROM stage_state ORDER BY stage").fetchall()]
            expired = [
                row["job_id"]
                for row in connection.execute(
                    "SELECT job_id FROM jobs WHERE status='leased' AND lease_until<=? ORDER BY job_id",
                    (now,),
                ).fetchall()
            ]
            dead_jobs = connection.execute("SELECT COUNT(*) FROM jobs WHERE status='dead'").fetchone()[0]
            pending_jobs = connection.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0]
            errors = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM pipeline_errors ORDER BY occurred_at DESC,error_id DESC LIMIT 20"
                ).fetchall()
            ]
            retention = self._retention_health(connection, now=now)
            offload_sync = self._offload_sync_health(connection)
            pipeline_errors = self._pipeline_error_health(connection)
        stale = [row["stage"] for row in stages if row["updated_at"] < stale_before]
        return {
            "stages": stages,
            "stale_stages": stale,
            "expired_leases": expired,
            "dead_jobs": dead_jobs,
            "pending_jobs": pending_jobs,
            "recent_errors": errors,
            "retention": retention,
            "offload_sync": offload_sync,
            "pipeline_errors": pipeline_errors,
        }

    @staticmethod
    def _pipeline_error_health(connection: sqlite3.Connection) -> dict[str, int]:
        row = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(retained_bytes),0),"
            "COALESCE(SUM(occurrence_count),0),"
            "COALESCE(SUM(CASE WHEN rate_limited=1 THEN occurrence_count ELSE 0 END),0) "
            "FROM pipeline_errors"
        ).fetchone()
        retained_count = int(row[0])
        occurrences = int(row[2])
        return {
            "retained_count": retained_count,
            "retained_bytes": int(row[1]),
            "total_occurrences": occurrences,
            "coalesced_occurrences": max(0, occurrences - retained_count),
            "rate_limited_occurrences": int(row[3]),
        }

    def _offload_sync_health(
        self, connection: sqlite3.Connection
    ) -> dict[str, Any]:
        session_ids = {
            str(row[0])
            for table in (
                "offload_sync_state",
                "offload_pending_calls",
                "offload_pair_queue",
                "offload_sync_dead_letters",
            )
            for row in connection.execute(f"SELECT DISTINCT session_id FROM {table}")
        }
        sessions = []
        for session_id in sorted(session_ids):
            state = connection.execute(
                "SELECT cursor_rowid,updated_at FROM offload_sync_state WHERE session_id=?",
                (session_id,),
            ).fetchone()
            cursor_rowid = int(state["cursor_rowid"]) if state is not None else 0
            counts = connection.execute(
                "SELECT "
                "SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END),"
                "SUM(CASE WHEN status='processed' THEN 1 ELSE 0 END),"
                "SUM(CASE WHEN status='dead' THEN 1 ELSE 0 END),"
                "MAX(CASE WHEN status='processed' THEN updated_at END) "
                "FROM offload_pair_queue WHERE session_id=?",
                (session_id,),
            ).fetchone()
            sessions.append(
                {
                    "session_digest": hashlib.sha256(
                        session_id.encode("utf-8")
                    ).hexdigest(),
                    "cursor_rowid": cursor_rowid,
                    "updated_at": (
                        str(state["updated_at"]) if state is not None else None
                    ),
                    "last_success_at": str(counts[3]) if counts[3] is not None else None,
                    "lag_rows": int(
                        connection.execute(
                            "SELECT COUNT(*) FROM evidence WHERE session_id=? AND rowid>? "
                            "AND evidence_type IN ('tool_call','tool_result')",
                            (session_id, cursor_rowid),
                        ).fetchone()[0]
                    ),
                    "pending_calls": int(
                        connection.execute(
                            "SELECT COUNT(*) FROM offload_pending_calls WHERE session_id=?",
                            (session_id,),
                        ).fetchone()[0]
                    ),
                    "retry_pairs": int(counts[0] or 0),
                    "processed_pairs": int(counts[1] or 0),
                    "dead_pairs": int(counts[2] or 0),
                    "dlq_count": int(
                        connection.execute(
                            "SELECT COUNT(*) FROM offload_sync_dead_letters WHERE session_id=?",
                            (session_id,),
                        ).fetchone()[0]
                    ),
                }
            )
        return {
            "session_count": len(sessions),
            "lag_rows": sum(item["lag_rows"] for item in sessions),
            "retry_pairs": sum(item["retry_pairs"] for item in sessions),
            "dlq_count": sum(item["dlq_count"] for item in sessions),
            "last_success_at": max(
                (
                    str(item["last_success_at"])
                    for item in sessions
                    if item["last_success_at"] is not None
                ),
                default=None,
            ),
            "sessions": sessions,
        }

    def _retention_health(
        self, connection: sqlite3.Connection, *, now: str
    ) -> dict[str, Any]:
        policy = self.retention_policy
        evidence = connection.execute(
            "SELECT COUNT(*) AS retained_count,"
            "COALESCE((SELECT retained_bytes FROM retention_usage "
            "WHERE storage_class='evidence' AND session_id=''),0) AS retained_bytes,"
            "MIN(captured_at) AS oldest_evidence FROM evidence"
        ).fetchone()
        candidates = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(claim AS BLOB)) + "
            "length(CAST(source_span AS BLOB))),0) FROM candidates"
        ).fetchone()
        offload = connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM offload_evidence) + (SELECT COUNT(*) FROM offload_tasks),"
            "COALESCE((SELECT SUM(retained_bytes) FROM offload_evidence),0) + "
            "COALESCE((SELECT SUM(retained_bytes) FROM offload_tasks),0)"
        ).fetchone()
        session_evidence = connection.execute(
            "SELECT COALESCE(MAX(item_count),0),COALESCE(MAX(retained_bytes),0) "
            "FROM retention_usage WHERE storage_class='evidence' AND session_id<>''"
        ).fetchone()
        session_offload = connection.execute(
            "SELECT COALESCE(MAX(row_count),0),COALESCE(MAX(row_bytes),0) FROM ("
            "SELECT COUNT(*) AS row_count,SUM(retained_bytes) AS row_bytes FROM ("
            "SELECT session_id,retained_bytes FROM offload_evidence UNION ALL "
            "SELECT session_id,retained_bytes FROM offload_tasks) GROUP BY session_id)"
        ).fetchone()
        actuals = {
            "evidence_count_per_session": int(session_evidence[0]),
            "evidence_bytes_per_session": int(session_evidence[1]),
            "evidence_count_global": int(evidence["retained_count"]),
            "evidence_bytes_global": int(evidence["retained_bytes"]),
            "offload_count_per_session": int(session_offload[0]),
            "offload_bytes_per_session": int(session_offload[1]),
            "offload_count_global": int(offload[0]),
            "offload_bytes_global": int(offload[1]),
        }
        limits = {
            "evidence_count_per_session": policy.evidence_max_count_per_session,
            "evidence_bytes_per_session": policy.evidence_max_bytes_per_session,
            "evidence_count_global": policy.evidence_max_count_global,
            "evidence_bytes_global": policy.evidence_max_bytes_global,
            "offload_count_per_session": policy.offload_max_count_per_session,
            "offload_bytes_per_session": policy.offload_max_bytes_per_session,
            "offload_count_global": policy.offload_max_count_global,
            "offload_bytes_global": policy.offload_max_bytes_global,
        }
        if any(actuals[key] > limits[key] for key in limits):
            quota_status = "violated"
        elif any(actuals[key] == limits[key] for key in limits):
            quota_status = "at_limit"
        else:
            quota_status = "ok"
        oldest = evidence["oldest_evidence"]
        purge_lag = 0
        if oldest is not None:
            expiry = _parse_timestamp(str(oldest)) + timedelta(
                seconds=policy.evidence_ttl_seconds
            )
            purge_lag = max(
                0, int((_parse_timestamp(now) - expiry).total_seconds())
            )
        failure_row = connection.execute(
            "SELECT receipt_json FROM retention_purge_receipts WHERE status='failed' "
            "ORDER BY updated_at DESC,receipt_id DESC LIMIT 1"
        ).fetchone()
        last_failure = (
            json.loads(str(failure_row["receipt_json"]))
            if failure_row is not None
            else None
        )
        evidence_bytes = int(evidence["retained_bytes"])
        candidate_bytes = int(candidates[1])
        offload_bytes = int(offload[1])
        gc_row = connection.execute(
            "SELECT * FROM retention_gc_state WHERE singleton=1"
        ).fetchone()
        gc_last_success = (
            str(gc_row["last_success_at"])
            if gc_row is not None and gc_row["last_success_at"] is not None
            else None
        )
        gc_overdue = False
        if gc_last_success is not None:
            gc_overdue = (
                _parse_timestamp(now) - _parse_timestamp(gc_last_success)
            ).total_seconds() > policy.gc_sla_seconds
        return {
            "retained_bytes": evidence_bytes + candidate_bytes + offload_bytes,
            "retained_count": int(evidence["retained_count"]) + int(candidates[0]) + int(offload[0]),
            "evidence_bytes": evidence_bytes,
            "candidate_bytes": candidate_bytes,
            "offload_bytes": offload_bytes,
            "oldest_evidence": oldest,
            "quota_state": {
                "state": quota_status,
                "actual": actuals,
                "limits": limits,
            },
            "purge_lag_seconds": purge_lag,
            "last_failure": last_failure,
            "gc": {
                "last_run_at": str(gc_row["last_run_at"]) if gc_row is not None else None,
                "last_success_at": gc_last_success,
                "cursor": str(gc_row["cursor"]) if gc_row is not None and gc_row["cursor"] is not None else None,
                "has_more": bool(gc_row["has_more"]) if gc_row is not None else False,
                "status": str(gc_row["status"]) if gc_row is not None else "never_run",
                "overdue": gc_overdue,
                "sla_seconds": policy.gc_sla_seconds,
            },
            "policy": asdict(policy),
            "policy_digest": self._policy_digest(),
        }

    def _redacted_offload_bundle(
        self, bundle: Mapping[str, object]
    ) -> dict[str, object]:
        """Verify, decode and redact every offload copy before any SQL bind."""

        try:
            if bundle.get("schema_version") != 1:
                raise ValueError("invalid schema")
            snapshot = bundle["snapshot"]
            evidence = bundle["evidence"]
            receipt = bundle["receipt"]
            if not isinstance(snapshot, dict) or not isinstance(evidence, list) or not isinstance(receipt, dict):
                raise ValueError("invalid shape")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid offload bundle") from error

        replacements: dict[str, str] = {}
        safe_evidence: list[dict[str, object]] = []
        for supplied in evidence:
            if not isinstance(supplied, dict):
                raise ValueError("invalid offload evidence")
            decoded = self._decode_offload_payload(supplied)
            safe_decoded = redact_value(decoded, self.redaction_policy)
            raw = canonical_json(safe_decoded).encode("utf-8")
            digest = hashlib.sha256(raw).hexdigest()
            evidence_ref = "sha256:" + digest
            old_ref = str(supplied["evidence_ref"])
            replacements[old_ref] = evidence_ref
            replacements[str(supplied["content_sha256"])] = digest
            safe_item = redact_value(dict(supplied), self.redaction_policy)
            if not isinstance(safe_item, dict):
                raise ValueError("invalid offload evidence metadata")
            safe_item.update(
                {
                    "evidence_ref": evidence_ref,
                    "content_sha256": digest,
                    "encoding": "gzip+base64+canonical-json",
                    "payload": base64.b64encode(
                        gzip.compress(raw, mtime=0)
                    ).decode("ascii"),
                    "source_ref": redact_text(
                        str(safe_decoded.get("source_ref") or ""),
                        self.redaction_policy,
                    ),
                }
            )
            safe_evidence.append(safe_item)

        replaced_snapshot = _replace_exact_strings(snapshot, replacements)
        safe_snapshot = redact_value(replaced_snapshot, self.redaction_policy)
        if not isinstance(safe_snapshot, dict):
            raise ValueError("invalid offload snapshot")
        snapshot_json = canonical_json(safe_snapshot)
        snapshot_digest = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()
        safe_receipt = redact_value(
            _replace_exact_strings(receipt, replacements), self.redaction_policy
        )
        if not isinstance(safe_receipt, dict):
            raise ValueError("invalid offload receipt")
        safe_receipt["task_id"] = safe_snapshot.get("task_id")
        safe_receipt["version"] = safe_snapshot.get("version")
        safe_receipt["expected_version"] = int(bundle["expected_version"])
        safe_receipt["snapshot_digest"] = snapshot_digest
        safe_receipt["evidence_refs"] = [
            item["evidence_ref"] for item in safe_evidence
        ]
        safe_receipt.pop("receipt_id", None)
        safe_receipt["receipt_id"] = "offload:" + hashlib.sha256(
            canonical_json(safe_receipt).encode("utf-8")
        ).hexdigest()
        return {
            "schema_version": 1,
            "expected_version": int(bundle["expected_version"]),
            "snapshot": safe_snapshot,
            "snapshot_digest": snapshot_digest,
            "evidence": safe_evidence,
            "receipt": safe_receipt,
        }

    def _decode_offload_payload(self, item: Mapping[str, object]) -> dict[str, object]:
        try:
            if item.get("encoding") != "gzip+base64+canonical-json":
                raise ValueError("unsupported encoding")
            payload = item["payload"]
            if not isinstance(payload, str):
                raise ValueError("payload is not text")
            max_expanded_bytes = min(
                self.retention_policy.offload_max_bytes_per_session,
                self.retention_policy.offload_max_bytes_global,
            )
            max_encoded_bytes = ((max_expanded_bytes + 1024) * 4 + 2) // 3
            if len(payload) > max_encoded_bytes:
                raise ValueError("compressed payload exceeds the size limit")
            compressed = base64.b64decode(payload, validate=True)
            if len(compressed) > max_expanded_bytes + 1024:
                raise ValueError("compressed payload exceeds the size limit")
            with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
                raw = stream.read(max_expanded_bytes + 1)
            if len(raw) > max_expanded_bytes:
                raise ValueError("expanded payload exceeds the size limit")
            digest = hashlib.sha256(raw).hexdigest()
            if str(item.get("content_sha256")) != digest:
                raise ValueError("digest mismatch")
            if str(item.get("evidence_ref")) != "sha256:" + digest:
                raise ValueError("reference mismatch")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("payload is not an object")
            return value
        except (KeyError, ValueError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("offload evidence failed integrity verification") from error

    @staticmethod
    def _offload_session_id(snapshot: Mapping[str, object]) -> str | None:
        session_id = snapshot.get("session_id")
        if isinstance(session_id, str) and session_id:
            return session_id
        task_id = str(snapshot.get("task_id") or "")
        if task_id.startswith("codex-session:"):
            return task_id[len("codex-session:") :]
        source_ref = str(snapshot.get("source_ref") or "")
        if source_ref.startswith("session:"):
            return source_ref[len("session:") :].split(":", 1)[0]
        return None

    def _ensure_offload_quota(
        self,
        connection: sqlite3.Connection,
        *,
        session_id: str | None,
        task_id: str,
        incoming_count: int,
        incoming_bytes: int,
        include_task_version: bool = True,
    ) -> None:
        policy = self.retention_policy
        task_versions = int(
            connection.execute(
                "SELECT COUNT(*) FROM offload_tasks WHERE task_id=?", (task_id,)
            ).fetchone()[0]
        )
        if include_task_version and task_versions + 1 > policy.task_versions_max_per_task:
            raise RetentionQuotaExceeded("offload task version quota exceeded")
        usage_keys = [""] + ([session_id] if session_id is not None else [])
        placeholders = ",".join("?" for _ in usage_keys)
        rows = {
            str(row["session_id"]): (int(row["item_count"]), int(row["retained_bytes"]))
            for row in connection.execute(
                "SELECT session_id,item_count,retained_bytes FROM retention_usage "
                "WHERE storage_class='offload' AND session_id IN ({})".format(placeholders),
                usage_keys,
            )
        }
        global_count, global_bytes = rows.get("", (0, 0))
        session_count, session_bytes = rows.get(session_id or "\x00", (0, 0))
        checks = (
            (session_count + incoming_count, policy.offload_max_count_per_session, "per_session_count"),
            (session_bytes + incoming_bytes, policy.offload_max_bytes_per_session, "per_session_bytes"),
            (global_count + incoming_count, policy.offload_max_count_global, "global_count"),
            (global_bytes + incoming_bytes, policy.offload_max_bytes_global, "global_bytes"),
        )
        exceeded = [name for actual, limit, name in checks if actual > limit]
        if exceeded:
            raise RetentionQuotaExceeded(
                "offload retention quota exceeded: " + ",".join(exceeded)
            )

    def _prune_offload_task_versions_for_append(
        self, connection: sqlite3.Connection, *, task_id: str
    ) -> None:
        """Keep bounded recent recovery snapshots while admitting one new CAS version."""

        keep_before_append = max(0, self.retention_policy.task_versions_max_per_task - 1)
        rows = connection.execute(
            "SELECT version FROM offload_tasks WHERE task_id=? "
            "ORDER BY version DESC",
            (task_id,),
        ).fetchall()
        stale_versions = [int(row["version"]) for row in rows[keep_before_append:]]
        if not stale_versions:
            return
        # The per-version commit receipt is coupled to the full derived
        # snapshot by a restrictive foreign key.  Pair-level sync receipts are
        # the durable audit trail and remain retained; retire the duplicate
        # commit receipts before removing their superseded snapshots.
        connection.executemany(
            "DELETE FROM offload_receipts WHERE task_id=? AND version=?",
            ((task_id, version) for version in stale_versions),
        )
        connection.executemany(
            "DELETE FROM offload_tasks WHERE task_id=? AND version=?",
            ((task_id, version) for version in stale_versions),
        )

    def commit_offload_bundle(self, bundle: dict[str, object]) -> dict[str, object]:
        """CAS-commit an offload snapshot, raw evidence and receipt atomically."""
        bundle = self._redacted_offload_bundle(bundle)
        try:
            if bundle.get("schema_version") != 1:
                raise ValueError("offload bundle schema is invalid")
            expected_version = int(bundle["expected_version"])
            snapshot = bundle["snapshot"]
            evidence = bundle["evidence"]
            receipt = bundle["receipt"]
            supplied_digest = str(bundle["snapshot_digest"])
            if not isinstance(snapshot, dict) or not isinstance(evidence, list) or not isinstance(receipt, dict):
                raise ValueError("offload bundle shape is invalid")
            task_id = str(snapshot["task_id"])
            version = int(snapshot["version"])
            receipt_id = str(receipt["receipt_id"])
            if not task_id or version != expected_version + 1:
                raise ValueError("offload version sequence is invalid")
            snapshot_json = canonical_json(snapshot)
            actual_digest = hashlib.sha256(snapshot_json.encode("utf-8")).hexdigest()
            if actual_digest != supplied_digest or receipt.get("snapshot_digest") != actual_digest:
                raise ValueError("offload snapshot digest is invalid")
            if receipt.get("task_id") != task_id or int(receipt.get("version", -1)) != version:
                raise ValueError("offload receipt does not bind snapshot")
            if int(receipt.get("expected_version", -1)) != expected_version:
                raise ValueError("offload receipt does not bind expected version")
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid offload bundle") from exc

        stamp = utc_now()
        with self._transaction() as connection:
            prior_receipt = connection.execute(
                "SELECT receipt_json FROM offload_receipts WHERE receipt_id=?", (receipt_id,)
            ).fetchone()
            if prior_receipt is not None:
                value = json.loads(prior_receipt["receipt_json"])
                if value != receipt:
                    raise ValueError("offload receipt id collision")
                return value
            current = connection.execute(
                "SELECT COALESCE(MAX(version),0) FROM offload_tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()[0]
            if current != expected_version:
                raise ValueError("offload optimistic version conflict")
            self._prune_offload_task_versions_for_append(
                connection, task_id=task_id
            )
            session_id = self._offload_session_id(snapshot)
            new_evidence = []
            for item in evidence:
                if not isinstance(item, dict):
                    raise ValueError("offload evidence is invalid")
                exists = connection.execute(
                    "SELECT 1 FROM offload_evidence WHERE evidence_ref=?",
                    (str(item.get("evidence_ref") or ""),),
                ).fetchone()
                if exists is None:
                    new_evidence.append(item)
            self._ensure_offload_quota(
                connection,
                session_id=session_id,
                task_id=task_id,
                incoming_count=1 + len(new_evidence),
                incoming_bytes=len(snapshot_json.encode("utf-8"))
                + sum(
                    len(str(item.get("payload") or "").encode("utf-8"))
                    + len(canonical_json(item).encode("utf-8"))
                    for item in new_evidence
                ),
            )
            for item in evidence:
                if not isinstance(item, dict):
                    raise ValueError("offload evidence is invalid")
                evidence_ref = str(item.get("evidence_ref", ""))
                digest = str(item.get("content_sha256", ""))
                if evidence_ref != f"sha256:{digest}" or len(digest) != 64:
                    raise ValueError("offload evidence reference is invalid")
                existing = connection.execute(
                    "SELECT evidence_json FROM offload_evidence WHERE evidence_ref=?",
                    (evidence_ref,),
                ).fetchone()
                item_json = canonical_json(item)
                if existing is not None:
                    if existing["evidence_json"] != item_json:
                        raise ValueError("offload evidence reference collision")
                    continue
                connection.execute(
                    """
                    INSERT INTO offload_evidence(
                        evidence_ref,content_sha256,encoding,payload,source_ref,evidence_json,created_at,
                        session_id,retained_bytes
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        evidence_ref, digest, str(item.get("encoding", "")),
                        str(item.get("payload", "")), str(item.get("source_ref", "")),
                        item_json,
                        stamp,
                        str(self._decode_offload_payload(item).get("session_id") or session_id or "") or None,
                        len(str(item.get("payload", "")).encode("utf-8"))
                        + len(item_json.encode("utf-8")),
                    ),
                )
            connection.execute(
                """
                INSERT INTO offload_tasks(
                    task_id,version,snapshot_json,snapshot_digest,created_at,session_id,retained_bytes
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    task_id,
                    version,
                    snapshot_json,
                    actual_digest,
                    stamp,
                    session_id,
                    len(snapshot_json.encode("utf-8")),
                ),
            )
            connection.execute(
                """
                INSERT INTO offload_receipts(
                    receipt_id,task_id,version,expected_version,receipt_json,created_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (receipt_id, task_id, version, expected_version, canonical_json(receipt), stamp),
            )
            connection.execute(
                """
                INSERT INTO stage_state(stage,cursor,status,updated_at) VALUES('offload',?,'ok',?)
                ON CONFLICT(stage) DO UPDATE SET cursor=excluded.cursor,status='ok',updated_at=excluded.updated_at
                """,
                (f"{task_id}:{version}", stamp),
            )
        return dict(receipt)

    def load_offload_task(
        self, task_id: str, version: int | None = None
    ) -> dict[str, object] | None:
        if version is None:
            sql = (
                "SELECT snapshot_json,snapshot_digest FROM offload_tasks "
                "WHERE task_id=? ORDER BY version DESC LIMIT 1"
            )
            parameters: tuple[object, ...] = (task_id,)
        else:
            sql = (
                "SELECT snapshot_json,snapshot_digest FROM offload_tasks "
                "WHERE task_id=? AND version=?"
            )
            parameters = (task_id, version)
        with self._connect() as connection:
            row = connection.execute(sql, parameters).fetchone()
        if row is None:
            return None
        digest = hashlib.sha256(row["snapshot_json"].encode("utf-8")).hexdigest()
        if digest != row["snapshot_digest"]:
            raise ValueError("offload snapshot failed integrity verification")
        value = json.loads(row["snapshot_json"])
        if not isinstance(value, dict):
            raise ValueError("offload snapshot is invalid")
        return value

    def load_offload_evidence(self, evidence_ref: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT evidence_json FROM offload_evidence WHERE evidence_ref=?",
                (evidence_ref,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(row["evidence_json"])
        if not isinstance(value, dict) or value.get("evidence_ref") != evidence_ref:
            raise ValueError("offload evidence metadata is invalid")
        return value

    def restore_offload_evidence(self, evidence: Mapping[str, object]) -> bool:
        """Idempotently restore one already-verified content-addressed object."""
        item = dict(evidence)
        decoded = self._decode_offload_payload(item)
        if canonical_json(redact_value(decoded, self.redaction_policy)) != canonical_json(decoded):
            raise ValueError("offload evidence replay must be redacted before restore")
        safe_item = redact_value(item, self.redaction_policy)
        if not isinstance(safe_item, dict) or canonical_json(safe_item) != canonical_json(item):
            raise ValueError("offload evidence metadata must be redacted before restore")
        evidence_ref = str(item.get("evidence_ref") or "")
        digest = str(item.get("content_sha256") or "")
        if evidence_ref != "sha256:" + digest or len(digest) != 64:
            raise ValueError("offload evidence reference is invalid")
        if item.get("encoding") != "gzip+base64+canonical-json":
            raise ValueError("offload evidence encoding is invalid")
        item_json = canonical_json(item)
        stamp = utc_now()
        with self._transaction() as connection:
            identity_digest = hashlib.sha256(
                ("offload_evidence\x00" + evidence_ref).encode("utf-8")
            ).hexdigest()
            purged = connection.execute(
                "SELECT 1 FROM retention_restore_tombstones "
                "WHERE identity_digest=?",
                (identity_digest,),
            ).fetchone()
            if purged is not None:
                raise RetentionPurgeError(
                    "purged offload evidence cannot be restored"
                )
            existing = connection.execute(
                "SELECT evidence_json FROM offload_evidence WHERE evidence_ref=?",
                (evidence_ref,),
            ).fetchone()
            if existing is not None:
                if existing["evidence_json"] != item_json:
                    raise ValueError("offload evidence reference collision")
                return False
            session_id = str(decoded.get("session_id") or "") or None
            self._ensure_offload_quota(
                connection,
                session_id=session_id,
                task_id=str(decoded.get("task_id") or "restored-evidence"),
                incoming_count=1,
                incoming_bytes=len(str(item.get("payload") or "").encode("utf-8"))
                + len(item_json.encode("utf-8")),
                include_task_version=False,
            )
            connection.execute(
                """
                INSERT INTO offload_evidence(
                    evidence_ref,content_sha256,encoding,payload,source_ref,evidence_json,created_at,
                    session_id,retained_bytes
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    evidence_ref, digest, str(item.get("encoding")),
                    str(item.get("payload") or ""), str(item.get("source_ref") or ""),
                    item_json,
                    stamp,
                    session_id,
                    len(str(item.get("payload") or "").encode("utf-8"))
                    + len(item_json.encode("utf-8")),
                ),
            )
        return True

    def list_offload_versions(self, task_id: str) -> list[int]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT version FROM offload_tasks WHERE task_id=? ORDER BY version",
                (task_id,),
            ).fetchall()
        return [int(row["version"]) for row in rows]

    @staticmethod
    def _job_dict(row: sqlite3.Row | None) -> dict[str, Any]:
        if row is None:
            raise KeyError("job not found")
        item = dict(row)
        item["payload"] = _decode_json(item.pop("payload_json"))
        item["result"] = _decode_json(item.pop("result_json"))
        return item

    @staticmethod
    def _insert_dead_letter(
        connection: sqlite3.Connection,
        job: sqlite3.Row,
        error_code: str,
        error_detail: str,
        failed_at: str,
    ) -> None:
        dead_letter_id = stable_id("dead", job["job_id"], job["attempts"])
        connection.execute(
            """
            INSERT OR IGNORE INTO dead_letters(
                dead_letter_id,job_id,attempt,error_code,error_detail,failed_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (dead_letter_id, job["job_id"], job["attempts"], error_code, error_detail, failed_at),
        )
