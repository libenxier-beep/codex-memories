from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .model import canonical_json, digest_object, sha256_bytes
from .recall_policy import RecallPolicy, RecallPolicyError, parse_recall_policy
from .repository import (
    _governed_git_environment,
    _repository_git_binding,
    _trusted_git_executable,
)
from .storage import fsync_directory


class ProjectionError(RuntimeError):
    pass


FRONTMATTER_LINE = re.compile(r"^([a-zA-Z][a-zA-Z0-9_-]*):\s*(.*?)\s*$")
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af]")
MAX_AUTHORITY_BYTES = 512 * 1024
MAX_AUTHORITY_ITEMS = 10_000
MAX_AUTHORITY_TOTAL_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_CHARS = 4000
MAX_QUERY_BYTES = 8 * 1024
MAX_QUERY_TOKENS = 128
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BODY_BEGIN = "<!-- BEGIN CANONICAL MEMORY BODY -->\n"
BODY_END = "\n<!-- END CANONICAL MEMORY BODY -->"


def _normalized_exact(value: object) -> str:
    return unicodedata.normalize("NFKC", str(value)).casefold().strip()


def _query_centered_evidence(
    text: str,
    query: str,
    tokens: Sequence[str],
    *,
    limit: int,
) -> Tuple[str, int, int, str]:
    """Return a bounded canonical window with stable line and heading identity."""

    if limit < 3:
        raise ProjectionError("evidence limit is invalid")
    folded = text.casefold()
    needles = [query.casefold().strip(), *(token.casefold() for token in tokens)]
    offset = -1
    matched_size = 0
    for needle in dict.fromkeys(value for value in needles if value):
        candidate = folded.find(needle)
        if candidate >= 0:
            offset = candidate
            matched_size = len(needle)
            break
    if len(text) <= limit:
        start, end = 0, len(text)
    elif offset < 0:
        start, end = 0, limit - 1
    else:
        content_budget = limit - 2
        start = max(0, offset - max(0, (content_budget - matched_size) // 3))
        end = min(len(text), start + content_budget)
        if end - start < content_budget:
            start = max(0, end - content_budget)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    excerpt = (prefix + text[start:end] + suffix)[:limit]
    start_line = text.count("\n", 0, start) + 1
    end_line = start_line + excerpt.count("\n")
    heading = "document"
    for line in text[: max(start, offset) if offset >= 0 else start].splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*$", line)
        if match is not None:
            heading = match.group(1).strip()
    return excerpt, start_line, end_line, heading


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if value is None or value == "":
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProjectionError("invalid temporal value: {}".format(value)) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def frontmatter(text: str) -> Dict[str, Any]:
    if not text.startswith("---\n"):
        return {}
    finish = text.find("\n---\n", 4)
    if finish < 0:
        raise ProjectionError("frontmatter is not closed")
    result: Dict[str, Any] = {}
    for line in text[4:finish].splitlines():
        if not line.strip():
            continue
        match = FRONTMATTER_LINE.fullmatch(line)
        if match is None:
            continue
        key, raw = match.groups()
        if raw in {"null", "~"}:
            result[key] = None
        elif raw.startswith("[") and raw.endswith("]"):
            try:
                value = json.loads(raw)
            except json.JSONDecodeError:
                value = []
            result[key] = value
        else:
            result[key] = raw.strip("'\"")
    return result


def _metadata_bool(value: object) -> bool:
    return str(value or "false").strip().casefold() == "true"


def _governance_bool(value: object, *, field: str, path: str) -> bool:
    if value is None:
        return False
    if isinstance(value, str) and value.strip().casefold() in {"true", "false"}:
        return value.strip().casefold() == "true"
    raise ProjectionError("{} metadata is invalid: {}".format(field, path))


def _canonical_body(text: str) -> Optional[str]:
    start = text.find(BODY_BEGIN)
    if start < 0:
        return None
    start += len(BODY_BEGIN)
    finish = text.find(BODY_END, start)
    if finish < 0:
        raise ProjectionError("canonical memory body marker is not closed")
    return text[start:finish]


class MemoryProjection:
    """Disposable committed-authority lexical projection with fail-closed recall."""

    def __init__(
        self,
        *,
        repository: Path,
        index_path: Path,
        authority_roots: Sequence[str],
        force_no_fts: bool = False,
    ) -> None:
        self.repository, self.git_dir, self.git_common_dir = _repository_git_binding(
            repository
        )
        self.index_path = index_path.resolve(strict=False)
        self.authority_roots = tuple(authority_roots)
        self.force_no_fts = force_no_fts
        self.git_executable = _trusted_git_executable()
        self.git_environment = _governed_git_environment()
        self.git_environment.update(
            {
                "GIT_DIR": str(self.git_dir),
                "GIT_WORK_TREE": str(self.repository),
                "GIT_COMMON_DIR": str(self.git_common_dir),
            }
        )
        if not self.authority_roots:
            raise ValueError("authority_roots are required")
        for root in self.authority_roots:
            path = PurePosixPath(root)
            if path.is_absolute() or len(path.parts) != 1 or path.parts[0] in {".", "..", "personal_knowledge", "control_plane"}:
                raise ValueError("unsafe authority root: {}".format(root))
        self._assert_git_binding()

    def _assert_git_binding(self) -> None:
        try:
            root, git_dir, common_dir = _repository_git_binding(self.repository)
        except (OSError, ValueError) as error:
            raise ProjectionError("repository Git binding is invalid") from error
        if (root, git_dir, common_dir) != (
            self.repository,
            self.git_dir,
            self.git_common_dir,
        ):
            raise ProjectionError("repository Git binding changed")
        inside = self._run_git("rev-parse", "--is-inside-work-tree").decode(
            "ascii", "strict"
        ).strip()
        top = self._run_git("rev-parse", "--show-toplevel").decode(
            "utf-8", "strict"
        ).strip()
        reported_git_dir = self._run_git("rev-parse", "--absolute-git-dir").decode(
            "utf-8", "strict"
        ).strip()
        reported_common = self._run_git(
            "rev-parse", "--path-format=absolute", "--git-common-dir"
        ).decode("utf-8", "strict").strip()
        if (
            inside != "true"
            or Path(top).resolve(strict=True) != self.repository
            or Path(reported_git_dir).resolve(strict=True) != self.git_dir
            or Path(reported_common).resolve(strict=True) != self.git_common_dir
        ):
            raise ProjectionError("repository Git binding does not match Git")

    def _run_git(self, *args: str) -> bytes:
        completed = subprocess.run(
            [self.git_executable, *args],
            cwd=self.repository,
            env=self.git_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0:
            raise ProjectionError(
                "git {} failed: {}".format(
                    args[0], completed.stderr.decode("utf-8", "replace")[-2000:]
                )
            )
        return completed.stdout

    def _git(self, *args: str) -> bytes:
        return self._run_git(*args)

    def _revision(self, revision: str = "HEAD") -> str:
        self._assert_git_binding()
        return self._git("rev-parse", "{}^{{commit}}".format(revision)).decode("ascii").strip()

    def _tree_blobs(self, revision: str, roots: Sequence[str]) -> List[Tuple[str, str, str]]:
        self._assert_git_binding()
        output = self._git("ls-tree", "-r", "-z", "--full-tree", revision, "--", *roots)
        rows: List[Tuple[str, str, str]] = []
        for raw in output.split(b"\0"):
            if not raw:
                continue
            metadata, encoded_path = raw.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = encoded_path.decode("utf-8", "strict")
            if object_type != "blob" or mode not in {"100644", "100755"}:
                continue
            rows.append((path, object_id, mode))
        return rows

    def _blob(self, object_id: str) -> bytes:
        size = int(self._git("cat-file", "-s", object_id).decode("ascii"))
        if size > MAX_AUTHORITY_BYTES:
            raise ProjectionError("authority blob exceeds size limit")
        content = self._git("cat-file", "blob", object_id)
        if len(content) != size:
            raise ProjectionError("authority blob size changed during read")
        return content

    def _items(self, revision: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()
        authority_bytes = 0
        default_scopes = {"core": "global", "platform": "platform", "learnings": "learning"}
        tree_blobs = self._tree_blobs(revision, self.authority_roots)
        blobs_by_path = {path: object_id for path, object_id, _mode in tree_blobs}
        for path, object_id, mode in tree_blobs:
            pure = PurePosixPath(path)
            if pure.suffix.lower() != ".md" or pure.parts[0] not in self.authority_roots:
                continue
            content = self._blob(object_id)
            authority_bytes += len(content)
            if len(items) >= MAX_AUTHORITY_ITEMS or authority_bytes > MAX_AUTHORITY_TOTAL_BYTES:
                raise ProjectionError("authority_budget_exceeded")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ProjectionError("authority file is not UTF-8: {}".format(path)) from error
            metadata = frontmatter(text)
            item_id = str(metadata.get("id") or ("doc_" + sha256_bytes(path.encode("utf-8"))[:24]))
            if item_id in seen_ids:
                raise ProjectionError("duplicate memory item id: {}".format(item_id))
            seen_ids.add(item_id)
            scope = str(metadata.get("scope") or default_scopes[pure.parts[0]])
            applies_to = str(metadata.get("applies_to") or "all")
            lifecycle = str(metadata.get("status") or "legacy")
            valid_from = metadata.get("valid_from")
            valid_to = metadata.get("valid_to")
            review_after = metadata.get("review_after")
            for temporal in (valid_from, valid_to, review_after):
                if temporal is not None:
                    parse_time(str(temporal))
            authority_sha256 = sha256_bytes(content)
            source_body = _canonical_body(text)
            claimed_content_sha256 = metadata.get("content_sha256")
            if claimed_content_sha256 is not None:
                claimed_content_sha256 = str(claimed_content_sha256)
                if SHA256.fullmatch(claimed_content_sha256) is None or source_body is None:
                    raise ProjectionError("canonical content digest is not verifiable: {}".format(path))
                if sha256_bytes(source_body.encode("utf-8")) != claimed_content_sha256:
                    raise ProjectionError("canonical content digest mismatch: {}".format(path))
            claimed_source_revision = metadata.get("source_revision_sha256")
            source_revision_path = metadata.get("source_revision_path")
            source_revision_binding_kind = "authority_blob"
            source_revision_binding_path = path
            source_revision_binding_blob_oid = object_id
            if claimed_source_revision is None:
                source_revision_sha256 = authority_sha256
            else:
                source_revision_sha256 = str(claimed_source_revision)
                if SHA256.fullmatch(source_revision_sha256) is None:
                    raise ProjectionError("source revision digest is invalid: {}".format(path))
                if source_revision_path is not None:
                    if not isinstance(source_revision_path, str):
                        raise ProjectionError(
                            "source revision cannot be reopened: {}".format(path)
                        )
                    source_path = PurePosixPath(source_revision_path)
                    if (
                        source_path.is_absolute()
                        or not source_path.parts
                        or source_path.parts[0] not in self.authority_roots
                        or any(part in {"", ".", ".."} for part in source_path.parts)
                        or source_revision_path not in blobs_by_path
                    ):
                        raise ProjectionError(
                            "source revision cannot be reopened: {}".format(path)
                        )
                    source_revision_binding_path = source_revision_path
                    source_revision_binding_blob_oid = blobs_by_path[source_revision_path]
                    reopened_source = self._blob(source_revision_binding_blob_oid)
                    if sha256_bytes(reopened_source) != source_revision_sha256:
                        raise ProjectionError(
                            "source revision reopen digest mismatch: {}".format(path)
                        )
                    source_revision_binding_kind = "authority_source_blob"
                elif (
                    source_body is not None
                    and sha256_bytes(source_body.encode("utf-8"))
                    == source_revision_sha256
                ):
                    source_revision_binding_kind = "canonical_body"
                else:
                    raise ProjectionError(
                        "source revision cannot be reopened: {}".format(path)
                    )
            reactivation_values: set[str] = set()
            reactivation = metadata.get("reactivates_tombstone")
            reactivations = metadata.get("reactivates_tombstones")
            if reactivation is not None:
                if (
                    not isinstance(reactivation, str)
                    or SAFE_IDENTIFIER.fullmatch(reactivation) is None
                ):
                    raise ProjectionError("reactivation metadata is invalid: {}".format(path))
                reactivation_values.add(reactivation)
            if reactivations is not None:
                if (
                    not isinstance(reactivations, list)
                    or not reactivations
                    or any(
                        not isinstance(value, str)
                        or SAFE_IDENTIFIER.fullmatch(value) is None
                        for value in reactivations
                    )
                    or len(set(reactivations)) != len(reactivations)
                ):
                    raise ProjectionError("reactivation metadata is invalid: {}".format(path))
                reactivation_values.update(reactivations)
            deleted = _governance_bool(metadata.get("deleted"), field="deleted", path=path)
            frontmatter_tombstone = _governance_bool(
                metadata.get("tombstone"), field="tombstone", path=path
            )
            legacy_trust = str(metadata.get("trust_class") or "canonical_legacy")
            authorization_state = str(
                metadata.get("authorization_state")
                or (
                    "user_approved"
                    if legacy_trust == "user_approved"
                    else "unapproved"
                    if legacy_trust == "source_bound_candidate"
                    else "not_required"
                )
            )
            provenance_trust = str(
                metadata.get("provenance_trust")
                or (
                    "source_bound_candidate"
                    if legacy_trust == "source_bound_candidate"
                    else "current_source_validated"
                    if legacy_trust == "user_approved"
                    else legacy_trust
                )
            )
            items.append(
                {
                    "item_id": item_id,
                    "authority_path": path,
                    "blob_oid": object_id,
                    "authority_sha256": authority_sha256,
                    "revision_sha256": source_revision_sha256,
                    "revision_binding_kind": source_revision_binding_kind,
                    "revision_binding_path": source_revision_binding_path,
                    "revision_binding_blob_oid": source_revision_binding_blob_oid,
                    "content_sha256": str(claimed_content_sha256 or authority_sha256),
                    "mode": mode,
                    "scope": scope,
                    "applies_to": applies_to,
                    "lifecycle": lifecycle,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "review_after": review_after,
                    # Retained as a compatibility projection only.  Recall
                    # authorization and provenance are governed independently.
                    "trust_class": legacy_trust,
                    "authorization_state": authorization_state,
                    "provenance_trust": provenance_trust,
                    "privacy_class": str(metadata.get("privacy_class") or "private_local"),
                    "deleted": deleted,
                    "reference_protected": _metadata_bool(metadata.get("reference_protected")),
                    "tombstoned": frontmatter_tombstone,
                    "reactivates_tombstones": sorted(reactivation_values),
                    "content": text,
                }
            )
        return items

    def _tombstones(self, revision: str) -> List[Dict[str, Any]]:
        tombstones: List[Dict[str, Any]] = []
        for path, object_id, _mode in self._tree_blobs(revision, ("lifecycle/tombstones",)):
            if PurePosixPath(path).suffix.lower() != ".json":
                continue
            try:
                value = json.loads(self._blob(object_id).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ProjectionError("invalid tombstone artifact: {}".format(path)) from error
            required = {
                "schema_version",
                "tombstone_id",
                "item_id",
                "authority_path",
                "authority_sha256",
                "reason",
                "approval_receipt",
                "created_at",
                "runtime_purge_binding",
            }
            if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1:
                raise ProjectionError("invalid tombstone shape: {}".format(path))
            authority_path = value.get("authority_path")
            authority_parts = PurePosixPath(authority_path).parts if isinstance(authority_path, str) else ()
            runtime_purge = value.get("runtime_purge_binding")
            runtime_purge_valid = (
                isinstance(runtime_purge, dict)
                and set(runtime_purge) == {
                    "schema_version", "scope", "target_candidate_ids",
                    "session_selector_digests",
                }
                and runtime_purge.get("schema_version") == 1
                and runtime_purge.get("scope") == "whole_sessions"
                and isinstance(runtime_purge.get("target_candidate_ids"), list)
                and bool(runtime_purge.get("target_candidate_ids"))
                and runtime_purge["target_candidate_ids"]
                == sorted(set(runtime_purge["target_candidate_ids"]))
                and all(
                    isinstance(item, str)
                    and re.fullmatch(r"cand_[0-9a-f]{64}", item) is not None
                    for item in runtime_purge["target_candidate_ids"]
                )
                and isinstance(runtime_purge.get("session_selector_digests"), list)
                and bool(runtime_purge.get("session_selector_digests"))
                and runtime_purge["session_selector_digests"]
                == sorted(set(runtime_purge["session_selector_digests"]))
                and all(
                    isinstance(item, str) and SHA256.fullmatch(item) is not None
                    for item in runtime_purge["session_selector_digests"]
                )
            )
            valid = (
                isinstance(value.get("tombstone_id"), str)
                and SAFE_IDENTIFIER.fullmatch(value["tombstone_id"]) is not None
                and isinstance(value.get("item_id"), str)
                and SAFE_IDENTIFIER.fullmatch(value["item_id"]) is not None
                and isinstance(authority_path, str)
                and not PurePosixPath(authority_path).is_absolute()
                and bool(authority_parts)
                and authority_parts[0] in self.authority_roots
                and all(part not in {"", ".", ".."} for part in authority_parts)
                and PurePosixPath(authority_path).suffix.lower() == ".md"
                and isinstance(value.get("authority_sha256"), str)
                and SHA256.fullmatch(value["authority_sha256"]) is not None
                and isinstance(value.get("reason"), str)
                and 0 < len(value["reason"].encode("utf-8")) <= 4096
                and isinstance(value.get("approval_receipt"), str)
                and SAFE_IDENTIFIER.fullmatch(value["approval_receipt"]) is not None
                and isinstance(value.get("created_at"), str)
                and runtime_purge_valid
            )
            if not valid:
                raise ProjectionError("invalid tombstone fields: {}".format(path))
            parse_time(value["created_at"])
            tombstones.append(dict(value))
        identifiers = [value["tombstone_id"] for value in tombstones]
        if len(set(identifiers)) != len(identifiers):
            raise ProjectionError("duplicate tombstone identifier")
        return tombstones

    def _committed_state(self, revision: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        items = self._items(revision)
        tombstones = self._tombstones(revision)
        by_id = {item["item_id"]: item for item in items}
        matched_reactivations: set[str] = set()
        for tombstone in tombstones:
            target = by_id.get(tombstone["item_id"])
            if target is None:
                continue
            if (
                target["authority_path"] == tombstone["authority_path"]
                and target["authority_sha256"] == tombstone["authority_sha256"]
            ):
                if tombstone["tombstone_id"] in target["reactivates_tombstones"]:
                    raise ProjectionError("explicit reactivation requires changed authority content")
                target["tombstoned"] = True
                continue
            if tombstone["tombstone_id"] in target["reactivates_tombstones"]:
                matched_reactivations.add(tombstone["tombstone_id"])
                continue
            raise ProjectionError(
                "tombstoned item changed without explicit reactivation: {}".format(
                    target["authority_path"]
                )
            )
        declared_reactivations = {
            identifier
            for item in items
            for identifier in item["reactivates_tombstones"]
        }
        if declared_reactivations != matched_reactivations:
            raise ProjectionError("explicit reactivation does not bind a committed tombstone")
        return items, tombstones

    @staticmethod
    def _manifest(
        source_revision: str,
        backend: str,
        items: Sequence[Mapping[str, Any]],
        tombstones: Sequence[Mapping[str, Any]],
        *,
        recall_policy: Mapping[str, Any],
        tombstoned_item_ids: Sequence[str],
        source_item_count: int,
    ) -> Dict[str, Any]:
        logical_items = [
            {
                key: item[key]
                for key in (
                    "item_id",
                    "authority_path",
                    "blob_oid",
                    "authority_sha256",
                    "revision_sha256",
                    "revision_binding_kind",
                    "revision_binding_path",
                    "revision_binding_blob_oid",
                    "content_sha256",
                    "mode",
                    "scope",
                    "applies_to",
                    "lifecycle",
                    "valid_from",
                    "valid_to",
                    "review_after",
                    "trust_class",
                    "authorization_state",
                    "provenance_trust",
                    "privacy_class",
                    "deleted",
                    "reference_protected",
                    "tombstoned",
                    "reactivates_tombstones",
                )
            }
            for item in sorted(items, key=lambda value: (str(value["item_id"]), str(value["authority_path"])))
        ]
        recall_policy_sha256 = digest_object(recall_policy)
        body = {
            "schema_version": 1,
            "source_revision": source_revision,
            "backend": backend,
            "items": logical_items,
            "tombstoned_item_ids": sorted(tombstoned_item_ids),
            "recall_policy_sha256": recall_policy_sha256,
            "source_item_count": source_item_count,
            "filtered_item_count": source_item_count - len(items),
        }
        body["projection_digest"] = digest_object(body)
        return body

    def build(
        self,
        revision: str = "HEAD",
        *,
        context: Mapping[str, Any] | RecallPolicy | None = None,
    ) -> Mapping[str, Any]:
        try:
            policy = parse_recall_policy(context)
        except RecallPolicyError as error:
            raise ProjectionError("recall_policy_invalid") from error
        policy_mapping = policy.to_mapping()
        recall_policy_sha256 = digest_object(policy_mapping)
        source_revision = self._revision(revision)
        source_items, tombstones = self._committed_state(source_revision)
        tombstoned_item_ids = sorted(
            item["item_id"] for item in source_items if item["tombstoned"]
        )
        items = [
            item
            for item in source_items
            if self._eligible(item, policy_mapping, policy.as_of)[0]
        ]

        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".memory-projection-", dir=str(self.index_path.parent))
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            connection = sqlite3.connect(str(temporary))
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute(
                    """CREATE TABLE items (
                        item_id TEXT PRIMARY KEY,
                        authority_path TEXT NOT NULL,
                        blob_oid TEXT NOT NULL,
                        authority_sha256 TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        scope TEXT NOT NULL,
                        applies_to TEXT NOT NULL,
                        lifecycle TEXT NOT NULL,
                        valid_from TEXT,
                        valid_to TEXT,
                        review_after TEXT,
                        trust_class TEXT NOT NULL,
                        reference_protected INTEGER NOT NULL,
                        tombstoned INTEGER NOT NULL,
                        content TEXT NOT NULL
                    )"""
                )
                connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                backend = "sqlite_bounded_lexical"
                if not self.force_no_fts:
                    try:
                        connection.execute(
                            "CREATE VIRTUAL TABLE items_fts USING fts5(item_id UNINDEXED, content, tokenize='unicode61 remove_diacritics 2')"
                        )
                    except sqlite3.OperationalError:
                        backend = "sqlite_bounded_lexical"
                    else:
                        backend = "sqlite_fts5"
                for item in items:
                    connection.execute(
                        "INSERT INTO items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            item["item_id"],
                            item["authority_path"],
                            item["blob_oid"],
                            item["authority_sha256"],
                            item["mode"],
                            item["scope"],
                            item["applies_to"],
                            item["lifecycle"],
                            item["valid_from"],
                            item["valid_to"],
                            item["review_after"],
                            item["trust_class"],
                            1 if item["reference_protected"] else 0,
                            1 if item["tombstoned"] else 0,
                            item["content"],
                        ),
                    )
                    if backend == "sqlite_fts5":
                        connection.execute(
                            "INSERT INTO items_fts (item_id, content) VALUES (?, ?)",
                            (item["item_id"], item["content"]),
                        )
                manifest = self._manifest(
                    source_revision,
                    backend,
                    items,
                    tombstones,
                    recall_policy=policy_mapping,
                    tombstoned_item_ids=tombstoned_item_ids,
                    source_item_count=len(source_items),
                )
                for key, value in (
                    ("schema_version", "1"),
                    ("source_revision", source_revision),
                    ("backend", backend),
                    ("projection_digest", manifest["projection_digest"]),
                    ("recall_policy_sha256", recall_policy_sha256),
                    ("recall_policy", canonical_json(policy_mapping).decode("utf-8")),
                    ("manifest", canonical_json(manifest).decode("utf-8")),
                ):
                    connection.execute("INSERT INTO metadata (key, value) VALUES (?, ?)", (key, value))
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(FULL)")
            finally:
                connection.close()
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            os.chmod(str(temporary), 0o600)
            os.replace(str(temporary), str(self.index_path))
            fsync_directory(self.index_path.parent)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return {
            "schema_version": 1,
            "status": "built",
            "backend": manifest["backend"],
            "source_revision": source_revision,
            "projection_digest": manifest["projection_digest"],
            "recall_policy_sha256": recall_policy_sha256,
            "item_count": len(items),
            "source_item_count": len(source_items),
            "filtered_item_count": len(source_items) - len(items),
            "tombstone_count": len(tombstones),
            "forbidden_row_count": sum(
                1
                for item in items
                if item["authority_path"].startswith(("personal_knowledge/", "control_plane/"))
            ),
        }

    def _connection(self) -> sqlite3.Connection:
        if not self.index_path.is_file() or self.index_path.is_symlink():
            raise ProjectionError("projection_unavailable")
        connection = sqlite3.connect("file:{}?mode=ro".format(self.index_path), uri=True)
        connection.row_factory = sqlite3.Row
        return connection

    def export_manifest(self) -> Mapping[str, Any]:
        connection = self._connection()
        try:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            current_revision = self._revision("HEAD")
            if metadata.get("source_revision") != current_revision:
                raise ProjectionError("projection source is stale")
            manifest, _items = self._verified_committed_projection(
                metadata,
                current_revision,
            )
            return manifest
        finally:
            connection.close()

    def _verified_committed_projection(
        self,
        metadata: Mapping[str, str],
        current_revision: str,
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        backend = metadata.get("backend")
        if backend not in {"sqlite_fts5", "sqlite_bounded_lexical"}:
            raise ProjectionError("projection backend is invalid")
        raw_manifest = metadata.get("manifest")
        if not isinstance(raw_manifest, str):
            raise ProjectionError("projection manifest is missing")
        try:
            manifest = json.loads(raw_manifest)
        except json.JSONDecodeError as error:
            raise ProjectionError("projection manifest is invalid") from error
        if not isinstance(manifest, dict):
            raise ProjectionError("projection manifest is invalid")
        raw_policy = metadata.get("recall_policy")
        try:
            policy_value = json.loads(raw_policy) if isinstance(raw_policy, str) else None
            policy = parse_recall_policy(policy_value)
        except (json.JSONDecodeError, RecallPolicyError) as error:
            raise ProjectionError("projection recall policy is invalid") from error
        policy_mapping = policy.to_mapping()
        recall_policy_sha256 = digest_object(policy_mapping)
        if metadata.get("recall_policy_sha256") != recall_policy_sha256:
            raise ProjectionError("projection recall policy binding is invalid")
        supplied = manifest.get("projection_digest")
        body = dict(manifest)
        body.pop("projection_digest", None)
        if supplied != digest_object(body):
            raise ProjectionError("projection manifest digest is invalid")
        source_items, tombstones = self._committed_state(current_revision)
        tombstoned_item_ids = sorted(
            item["item_id"] for item in source_items if item["tombstoned"]
        )
        items = [
            item
            for item in source_items
            if self._eligible(item, policy_mapping, policy.as_of)[0]
        ]
        canonical = self._manifest(
            current_revision,
            backend,
            items,
            tombstones,
            recall_policy=policy_mapping,
            tombstoned_item_ids=tombstoned_item_ids,
            source_item_count=len(source_items),
        )
        if (
            manifest != canonical
            or metadata.get("projection_digest") != canonical["projection_digest"]
        ):
            raise ProjectionError("projection manifest does not match committed authority")
        return canonical, items

    @staticmethod
    def _governance_reasons(
        row: Mapping[str, Any], context: Mapping[str, Any], now: datetime
    ) -> List[str]:
        reasons: List[str] = []
        scopes = context.get("scopes")
        if not isinstance(scopes, list) or row["scope"] not in scopes:
            reasons.append("scope")
        requested_platform = context.get("applies_to")
        if row["applies_to"] != "all" and row["applies_to"] != requested_platform:
            reasons.append("applies_to")
        valid_from = parse_time(row["valid_from"])
        valid_to = parse_time(row["valid_to"])
        if valid_from is not None and now < valid_from:
            reasons.append("not_yet_valid")
        if valid_to is not None and now >= valid_to:
            reasons.append("expired")
        eligible_lifecycles = context.get("eligible_lifecycles")
        if not isinstance(eligible_lifecycles, list) or row["lifecycle"] not in eligible_lifecycles:
            reasons.append("lifecycle")
        allowed_authorization = context.get("allowed_authorization_states")
        if (
            not isinstance(allowed_authorization, list)
            or row["authorization_state"] not in allowed_authorization
        ):
            reasons.append("authorization")
        allowed_provenance = context.get("allowed_provenance_trust")
        if (
            not isinstance(allowed_provenance, list)
            or row["provenance_trust"] not in allowed_provenance
        ):
            reasons.append("provenance_trust")
        if context.get("high_stakes") is True and row["authorization_state"] != "user_approved":
            reasons.append("authorization")
        allowed_privacy = context.get("allowed_privacy_classes")
        if not isinstance(allowed_privacy, list) or row["privacy_class"] not in allowed_privacy:
            reasons.append("privacy")
        if row.get("deleted") is True:
            reasons.append("deleted")
        if row["tombstoned"]:
            reasons.append("tombstone")
        if SHA256.fullmatch(str(row.get("revision_sha256", ""))) is None:
            reasons.append("source_revision")
        if SHA256.fullmatch(str(row.get("content_sha256", ""))) is None:
            reasons.append("content_hash")
        return sorted(set(reasons))

    @classmethod
    def _eligible(
        cls, row: Mapping[str, Any], context: Mapping[str, Any], now: datetime
    ) -> Tuple[bool, Optional[str]]:
        reasons = cls._governance_reasons(row, context, now)
        return (not reasons, reasons[0] if reasons else None)

    @classmethod
    def _governance_trace(
        cls,
        items: Sequence[Mapping[str, Any]],
        context: Mapping[str, Any],
        now: datetime,
        *,
        stage: str,
    ) -> List[Dict[str, Any]]:
        trace: List[Dict[str, Any]] = []
        for row in sorted(items, key=lambda item: str(item["item_id"])):
            reasons = cls._governance_reasons(row, context, now)
            reason_set = set(reasons)
            checks = {
                "scope": not bool(reason_set & {"scope", "applies_to"}),
                "time": not bool(reason_set & {"not_yet_valid", "expired"}),
                "lifecycle": "lifecycle" not in reason_set,
                "authorization": "authorization" not in reason_set,
                "provenance_trust": "provenance_trust" not in reason_set,
                "trust": not bool(reason_set & {"authorization", "provenance_trust"}),
                "privacy": not bool(reason_set & {"privacy", "privacy_boundary"}),
                "tombstone": not bool(reason_set & {"deleted", "tombstone"}),
                "source_integrity": not bool(
                    reason_set & {"source_revision", "content_hash"}
                ),
            }
            trace.append({
                "id": str(row["item_id"]),
                "stage": stage,
                "checks": checks,
                "result": "eligible" if all(checks.values()) else "filtered",
                "reason_codes": reasons,
                "authority_revision_sha256": str(row["revision_sha256"]),
            })
        return trace

    def recall(
        self,
        query: str,
        *,
        context: Mapping[str, Any] | RecallPolicy | None = None,
        limit: int = 5,
    ) -> Mapping[str, Any]:
        try:
            policy = parse_recall_policy(context)
        except RecallPolicyError:
            return {
                "schema_version": 1,
                "status": "abstain",
                "reason": "recall_policy_invalid",
                "matches": [],
            }
        context = policy.to_mapping()
        if not isinstance(query, str) or not query.strip() or limit <= 0 or limit > 20:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": []}
        try:
            query_bytes = len(query.encode("utf-8"))
        except UnicodeEncodeError:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": []}
        if query_bytes > MAX_QUERY_BYTES:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_too_large"], "matches": []}
        tokens = sorted(set(TOKEN.findall(query.casefold())))
        if not tokens:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": []}
        if len(tokens) > MAX_QUERY_TOKENS:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_too_large"], "matches": []}
        current_revision = self._revision("HEAD")
        connection = self._connection()
        try:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if metadata.get("source_revision") != current_revision:
                return {
                    "schema_version": 1,
                    "status": "abstain",
                    "reason": "source_stale",
                    "matches": [],
                }
            if metadata.get("recall_policy_sha256") != digest_object(context):
                return {
                    "schema_version": 1,
                    "status": "abstain",
                    "reason": "recall_policy_mismatch",
                    "matches": [],
                }
            backend = metadata.get("backend")
            try:
                _manifest, canonical_items = self._verified_committed_projection(
                    metadata,
                    current_revision,
                )
            except ProjectionError:
                return {
                    "schema_version": 1,
                    "status": "abstain",
                    "reason": "projection_integrity_invalid",
                    "matches": [],
                }
            canonical_by_id = {item["item_id"]: item for item in canonical_items}
            checked_at = policy.as_of
            reasons: List[str] = []
            maximum_candidates = min(limit * 10, 200)

            exact_channels_by_id: Dict[str, List[str]] = {}
            normalized_query = _normalized_exact(query)
            for identifier, item in canonical_by_id.items():
                path = str(item["authority_path"])
                channels: List[str] = []
                if _normalized_exact(path) == normalized_query:
                    channels.append("exact_path")
                if _normalized_exact(Path(path).name) == normalized_query:
                    channels.append("exact_name")
                if channels:
                    exact_channels_by_id[str(identifier)] = channels

            def eligible_canonical_item(
                identifier: object, *, require_content_match: bool = True
            ) -> Optional[Dict[str, Any]]:
                item = canonical_by_id.get(str(identifier))
                if item is None:
                    reasons.append("index_candidate_invalid")
                    return None
                folded_content = str(item["content"]).casefold()
                if require_content_match and not any(
                    token in folded_content for token in tokens
                ):
                    reasons.append("index_candidate_mismatch")
                    return None
                eligible, reason = self._eligible(item, context, checked_at)
                if not eligible:
                    if reason:
                        reasons.append(reason)
                    return None
                return item

            rows = []
            seen_candidate_ids: set[str] = set()
            for candidate_id in sorted(exact_channels_by_id):
                item = eligible_canonical_item(
                    candidate_id, require_content_match=False
                )
                if item is None:
                    continue
                rows.append({"item_id": str(item["item_id"])})
                seen_candidate_ids.add(str(item["item_id"]))

            if backend == "sqlite_fts5":
                expression = " OR ".join('"{}"'.format(token.replace('"', '""')) for token in tokens)
                seen_fts_ids: set[str] = set(seen_candidate_ids)
                for row in connection.execute(
                    """SELECT item_id, bm25(items_fts) AS rank
                       FROM items_fts
                       WHERE items_fts MATCH ?
                       ORDER BY rank ASC, item_id ASC""",
                    (expression,),
                ):
                    item = eligible_canonical_item(row["item_id"])
                    if item is None or item["item_id"] in seen_fts_ids:
                        continue
                    seen_fts_ids.add(str(item["item_id"]))
                    rows.append({"item_id": item["item_id"]})
                    if len(rows) >= maximum_candidates:
                        break
                # unicode61 treats a contiguous Han run as one token, so a
                # short query such as “授权” cannot MATCH “显式授权”.  The
                # projection is only a candidate source; bounded substring
                # scoring over freshly reopened committed authority restores
                # this CJK lane without trusting mutable indexed content.
                if CJK.search(query) and len(rows) < maximum_candidates:
                    fallback: List[Tuple[int, str]] = []
                    for candidate_id in sorted(canonical_by_id):
                        if candidate_id in seen_fts_ids:
                            continue
                        item = eligible_canonical_item(candidate_id)
                        if item is None:
                            continue
                        folded = str(item["content"]).casefold()
                        score = sum(folded.count(token) for token in tokens)
                        if score > 0:
                            fallback.append((score, candidate_id))
                    fallback.sort(key=lambda value: (-value[0], value[1]))
                    rows.extend(
                        {"item_id": item_id}
                        for _score, item_id in fallback[: maximum_candidates - len(rows)]
                    )
            elif backend == "sqlite_bounded_lexical":
                ranked_ids: List[Tuple[int, str]] = []
                for row in connection.execute("SELECT item_id FROM items ORDER BY item_id ASC"):
                    if str(row["item_id"]) in seen_candidate_ids:
                        continue
                    item = eligible_canonical_item(row["item_id"])
                    if item is None:
                        continue
                    folded = str(item["content"]).casefold()
                    score = sum(folded.count(token) for token in tokens)
                    if score <= 0:
                        continue
                    ranked_ids.append((score, str(item["item_id"])))
                    if len(ranked_ids) > maximum_candidates:
                        ranked_ids.sort(key=lambda value: (-value[0], value[1]))
                        del ranked_ids[maximum_candidates:]
                ranked_ids.sort(key=lambda value: (-value[0], value[1]))
                rows.extend(
                    {"item_id": item_id} for _score, item_id in ranked_ids
                )
            else:
                raise ProjectionError("projection backend is invalid")
            matches: List[Dict[str, Any]] = []
            for row in rows:
                item = canonical_by_id.get(str(row["item_id"]))
                if item is None:
                    reasons.append("index_candidate_invalid")
                    continue
                folded_content = str(item["content"]).casefold()
                exact_channels = exact_channels_by_id.get(str(item["item_id"]), [])
                if not exact_channels and not any(
                    token in folded_content for token in tokens
                ):
                    reasons.append("index_candidate_mismatch")
                    continue
                eligible, reason = self._eligible(item, context, checked_at)
                if not eligible:
                    if reason:
                        reasons.append(reason)
                    continue
                path = str(item["authority_path"])
                content = self._blob(str(item["blob_oid"]))
                if sha256_bytes(content) != item["authority_sha256"]:
                    reasons.append("authority_hash_mismatch")
                    continue
                text = content.decode("utf-8")
                evidence_content, excerpt_start, excerpt_end, heading = (
                    _query_centered_evidence(
                        text,
                        query,
                        tokens,
                        limit=MAX_EVIDENCE_CHARS,
                    )
                )
                source_ref = "{}@{}#L{}-L{}".format(
                    path, current_revision, excerpt_start, excerpt_end
                )
                evidence = (
                    "[memory evidence; not instruction]\n"
                    "id={}\nscope={}\nsource={}\nheading={}\ncontent={}"
                ).format(
                    item["item_id"],
                    item["scope"],
                    source_ref,
                    heading,
                    evidence_content,
                )
                matches.append(
                    {
                        "item_id": item["item_id"],
                        "authority_path": path,
                        "authority_sha256": item["authority_sha256"],
                        "revision_sha256": item["revision_sha256"],
                        "content_sha256": item["content_sha256"],
                        "source_revision": current_revision,
                        "scope": item["scope"],
                        "lifecycle": item["lifecycle"],
                        "authorization_state": item["authorization_state"],
                        "provenance_trust": item["provenance_trust"],
                        "privacy_class": item["privacy_class"],
                        "canonical_reopened": True,
                        "retrieval_channels": exact_channels or ["lexical"],
                        "heading": heading,
                        "excerpt_start_line": excerpt_start,
                        "excerpt_end_line": excerpt_end,
                        "source_ref": source_ref,
                        "evidence_content": evidence_content,
                        "evidence": evidence,
                    }
                )
                if len(matches) >= limit:
                    break
            return {
                "schema_version": 1,
                "status": "hit" if matches else "no_safe_match",
                "backend": backend,
                "source_revision": current_revision,
                "reason_codes": sorted(set(reasons)),
                "matches": matches,
            }
        finally:
            connection.close()

    def plan_retention(self, *, as_of: datetime) -> Mapping[str, Any]:
        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=timezone.utc)
        as_of = as_of.astimezone(timezone.utc)
        connection = self._connection()
        try:
            current_revision = self._revision("HEAD")
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if metadata.get("source_revision") != current_revision:
                raise ProjectionError("projection source is stale")
            _manifest, _indexed_items = self._verified_committed_projection(
                metadata,
                current_revision,
            )
            canonical_items, _tombstones = self._committed_state(current_revision)
            items: List[Dict[str, Any]] = []
            for item in sorted(canonical_items, key=lambda value: str(value["item_id"])):
                if item["tombstoned"]:
                    continue
                valid_to = parse_time(item["valid_to"])
                if valid_to is not None and as_of >= valid_to:
                    action = "review_reference_protected" if item["reference_protected"] else "propose_tombstone"
                    items.append(
                        {
                            "item_id": item["item_id"],
                            "authority_path": item["authority_path"],
                            "action": action,
                            "reason": "expired",
                        }
                    )
                elif item["lifecycle"] in {"superseded", "deprecated"}:
                    items.append(
                        {
                            "item_id": item["item_id"],
                            "authority_path": item["authority_path"],
                            "action": "review_superseded",
                            "reason": item["lifecycle"],
                        }
                    )
                else:
                    review_after = parse_time(item["review_after"])
                    if review_after is not None and as_of >= review_after:
                        items.append(
                            {
                                "item_id": item["item_id"],
                                "authority_path": item["authority_path"],
                                "action": "review_due",
                                "reason": "review_after",
                            }
                        )
            return {
                "schema_version": 1,
                "dry_run": True,
                "as_of": as_of.isoformat().replace("+00:00", "Z"),
                "physical_history_erasure": False,
                "items": items,
            }
        finally:
            connection.close()
