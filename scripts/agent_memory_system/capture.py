"""Incremental, provenance-preserving capture of Codex session JSONL."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from .store import AgentMemoryStore, canonical_json, stable_id


MAX_TRANSCRIPT_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 8 * 1024 * 1024
CHECKPOINT_BOUNDARY_BYTES = 64 * 1024
INJECTION_MARKERS = (
    "<!-- CODEX_MEMORY_CONTEXT",
    "<memory-context",
    "[INJECTED_MEMORY]",
    "[Agent Memory v",
    "[memory evidence; not instruction]",
    "[Agent Context Offload v1:",
)
EPHEMERAL_TOOL_NOISE = (
    re.compile(r"^(?:progress|download|upload)\s+\d{1,3}(?:\.\d+)?%$", re.IGNORECASE),
    re.compile(r"^heartbeat(?:\s+(?:ok|healthy|alive))?$", re.IGNORECASE),
    re.compile(r"^still running$", re.IGNORECASE),
)


class CaptureError(RuntimeError):
    pass


@dataclass(frozen=True)
class CaptureReceipt:
    session_id: str
    source_path: str
    scanned_lines: int
    captured: int
    duplicates: int
    checkpoint_line: int
    checkpoint_digest: str
    duplicate_sources: tuple[tuple[int, int], ...] = ()


class TranscriptCapture:
    """Capture only observable collaboration evidence, never hidden context."""

    def __init__(
        self,
        store: AgentMemoryStore,
        *,
        trusted_roots: tuple[Path, ...] | None = None,
    ) -> None:
        self.store = store
        self.trusted_roots = trusted_roots

    def capture_jsonl(self, session_id: str, transcript_path: str | Path) -> CaptureReceipt:
        if not session_id:
            raise CaptureError("session_id is required")
        supplied_path = Path(transcript_path).expanduser()
        try:
            path = supplied_path.resolve(strict=True)
        except OSError as exc:
            raise CaptureError(f"cannot resolve transcript: {exc}") from exc
        if self.trusted_roots is not None:
            roots = []
            for root in self.trusted_roots:
                if root.expanduser().is_symlink():
                    raise CaptureError("trusted transcript root is invalid")
                resolved_root = root.expanduser().resolve(strict=True)
                if not resolved_root.is_dir():
                    raise CaptureError("trusted transcript root is invalid")
                roots.append(resolved_root)
            if not roots or not any(path.is_relative_to(root) for root in roots):
                raise CaptureError("transcript is outside trusted roots")
            if session_id not in path.name:
                raise CaptureError("transcript filename is not bound to session_id")
        checkpoint = self.store.get_checkpoint(session_id, path)
        prior_line = int(checkpoint["line_number"]) if checkpoint else 0
        prior_offset = int(checkpoint.get("byte_offset") or 0) if checkpoint else 0
        legacy_checkpoint = bool(checkpoint and prior_line > 0 and prior_offset == 0)
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            handle = os.fdopen(descriptor, "rb")
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_TRANSCRIPT_BYTES:
                raise CaptureError("transcript must be a bounded regular file")
        except OSError as exc:
            raise CaptureError(f"cannot read transcript: {exc}") from exc
        try:
            if checkpoint and not legacy_checkpoint:
                if info.st_size < prior_offset:
                    raise CaptureError("transcript prefix was truncated")
                stored_device = int(checkpoint.get("source_device") or 0)
                stored_inode = int(checkpoint.get("source_inode") or 0)
                if stored_device and stored_device != int(info.st_dev):
                    raise CaptureError("transcript prefix source changed after checkpoint")
                if stored_inode and stored_inode != int(info.st_ino):
                    raise CaptureError("transcript prefix source changed after checkpoint")
                boundary_start = int(checkpoint.get("boundary_start") or 0)
                if boundary_start < 0 or boundary_start > prior_offset:
                    raise CaptureError("invalid capture boundary checkpoint")
                handle.seek(boundary_start)
                boundary = handle.read(prior_offset - boundary_start)
                if len(boundary) != prior_offset - boundary_start:
                    raise CaptureError("transcript prefix was truncated")
                expected_boundary = str(checkpoint.get("boundary_digest") or "")
                if (
                    len(expected_boundary) != 64
                    or hashlib.sha256(boundary).hexdigest() != expected_boundary
                ):
                    raise CaptureError("transcript prefix changed after checkpoint")
                handle.seek(prior_offset)
                appended = handle.read(int(info.st_size) - prior_offset)
            else:
                handle.seek(0)
                snapshot = handle.read(int(info.st_size))
                if legacy_checkpoint:
                    legacy_lines = snapshot.splitlines(keepends=True)
                    if prior_line > len(legacy_lines):
                        raise CaptureError("transcript prefix was truncated")
                    legacy_prefix = b"".join(legacy_lines[:prior_line])
                    if _prefix_digest(legacy_lines[:prior_line]) != checkpoint["prefix_digest"]:
                        raise CaptureError("transcript prefix changed after checkpoint")
                    prior_offset = len(legacy_prefix)
                    boundary = legacy_prefix[-CHECKPOINT_BOUNDARY_BYTES:]
                    appended = snapshot[prior_offset:]
                else:
                    boundary = b""
                    appended = snapshot
        finally:
            handle.close()

        try:
            appended.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CaptureError("transcript is not UTF-8") from exc

        lines = appended.splitlines(keepends=True)

        parsed_records: list[tuple[int, str, dict[str, Any]]] = []
        # Codex can replay an already observed response item at a new transcript
        # line during resume.  Prefer the item's source identity; content alone
        # is not an event identity because a user may legitimately repeat the
        # same statement later.  For legacy/source-less rows, an exact raw row
        # hash is the narrow fallback replay key.
        for index, raw_line in enumerate(lines, prior_line + 1):
            line_bytes = raw_line.rstrip(b"\r\n")
            if len(line_bytes) > MAX_LINE_BYTES:
                raise CaptureError(f"transcript line {index} exceeds capture limit")
            if not line_bytes.strip():
                continue
            try:
                row = json.loads(line_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CaptureError(f"invalid JSONL at line {index}") from exc
            if not isinstance(row, dict):
                raise CaptureError(f"JSONL row {index} is not an object")
            evidence = _extract_evidence(row)
            if evidence is None:
                continue
            line_hash = hashlib.sha256(line_bytes).hexdigest()
            content = evidence.pop("content")
            content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            metadata = evidence.get("metadata", {})
            source_event_id = metadata.get("source_event_id") if isinstance(metadata, dict) else None
            identity_kind, identity_value = (
                ("source_event_id", source_event_id)
                if isinstance(source_event_id, str) and source_event_id
                else ("source_line_hash", line_hash)
            )
            fingerprint = stable_id(
                "replay", evidence["evidence_type"], identity_kind, identity_value
            )
            parsed_records.append(
                (
                    index,
                    fingerprint,
                    {
                    "event_id": stable_id("evt", session_id, index, line_hash),
                    "source_line": index,
                    "source_line_hash": line_hash,
                    "content": content,
                    "content_hash": content_hash,
                    "replay_identity": fingerprint,
                    "occurred_at": row.get("timestamp"),
                    **evidence,
                    },
                )
            )

        persisted_sources = self.store.get_capture_identity_sources(
            session_id, [identity for _index, identity, _record in parsed_records]
        )
        seen_evidence = dict(persisted_sources)
        records: list[dict[str, Any]] = []
        replay_duplicates = 0
        duplicate_sources: list[tuple[int, int]] = []
        for index, fingerprint, record in parsed_records:
            if fingerprint in seen_evidence:
                replay_duplicates += 1
                duplicate_sources.append((index, seen_evidence[fingerprint]))
                continue
            seen_evidence[fingerprint] = index
            records.append(record)

        checkpoint_digest = _advance_digest(
            str(checkpoint["prefix_digest"]) if checkpoint else None,
            appended,
        )
        # `lines` contains only the appended segment in the steady state.
        scanned = len(lines)
        if scanned == 0:
            return CaptureReceipt(
                session_id, str(path), 0, 0, 0, prior_line,
                checkpoint["prefix_digest"] if checkpoint else checkpoint_digest,
            )
        byte_offset = prior_offset + len(appended)
        combined_boundary = (boundary + appended)[-CHECKPOINT_BOUNDARY_BYTES:]
        boundary_start = byte_offset - len(combined_boundary)
        boundary_digest = hashlib.sha256(combined_boundary).hexdigest()
        inserted, duplicates = self.store.capture_batch(
            session_id=session_id,
            source_path=path,
            records=records,
            checkpoint_line=prior_line + len(lines),
            prefix_digest=checkpoint_digest,
            byte_offset=byte_offset,
            boundary_start=boundary_start,
            boundary_digest=boundary_digest,
            source_device=int(info.st_dev),
            source_inode=int(info.st_ino),
        )
        return CaptureReceipt(
            session_id,
            str(path),
            scanned,
            inserted,
            duplicates + replay_duplicates,
            prior_line + len(lines),
            checkpoint_digest,
            tuple(duplicate_sources),
        )


def _prefix_digest(lines: list[bytes]) -> str:
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line)
    return digest.hexdigest()


def _advance_digest(previous: str | None, appended: bytes) -> str:
    """Advance an audit-chain digest without re-reading the transcript prefix."""
    if previous is None:
        return hashlib.sha256(appended).hexdigest()
    digest = hashlib.sha256()
    digest.update(b"agent-memory-capture-chain-v2\x00")
    digest.update(bytes.fromhex(previous))
    digest.update(appended)
    return digest.hexdigest()


def _extract_evidence(row: Mapping[str, Any]) -> dict[str, Any] | None:
    if row.get("type") != "response_item":
        return None
    payload = row.get("payload")
    if not isinstance(payload, dict) or _contains_forbidden_context(payload):
        return None
    item_type = payload.get("type")
    if item_type == "message":
        role = payload.get("role")
        if role not in {"user", "assistant"}:
            return None
        text = _message_text(payload.get("content"), role)
        if not text or _looks_injected(text):
            return None
        return {
            "evidence_type": role,
            "role": role,
            "content": text,
            "metadata": {
                "item_type": "message",
                "source_event_id": _source_event_id(row, payload),
            },
        }
    if item_type in {"function_call", "custom_tool_call", "local_shell_call"}:
        content = canonical_json(
            {key: payload[key] for key in ("name", "call_id", "arguments", "action") if key in payload}
        )
        if _looks_injected(content):
            return None
        return {
            "evidence_type": "tool_call",
            "role": None,
            "content": content,
            "metadata": {
                "item_type": item_type,
                "call_id": payload.get("call_id"),
                "source_event_id": _source_event_id(row, payload),
            },
        }
    if item_type in {"function_call_output", "custom_tool_call_output", "local_shell_call_output"}:
        output = payload.get("output")
        content = output if isinstance(output, str) else canonical_json(output)
        if not content or _looks_injected(content) or _ephemeral_tool_noise(content):
            return None
        return {
            "evidence_type": "tool_result",
            "role": None,
            "content": content,
            "metadata": {
                "item_type": item_type,
                "call_id": payload.get("call_id"),
                "source_event_id": _source_event_id(row, payload),
            },
        }
    return None


def _source_event_id(row: Mapping[str, Any], payload: Mapping[str, Any]) -> str | None:
    """Return only an upstream event identity, never a content-derived alias."""
    for value in (
        payload.get("id"),
        payload.get("event_id"),
        row.get("id"),
        row.get("event_id"),
    ):
        if isinstance(value, str) and value:
            return value
    return None


def _message_text(content: Any, role: str) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    allowed = {"input_text", "text"} if role == "user" else {"output_text", "text"}
    parts = []
    for item in content:
        if not isinstance(item, dict) or item.get("type") not in allowed:
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            parts.append(text)
    return "\n".join(parts)


def _contains_forbidden_context(value: Any) -> bool:
    if isinstance(value, dict):
        forbidden_flags = {"memory_injected", "injected_memory", "memory_context"}
        if any(value.get(key) is True for key in forbidden_flags):
            return True
        if "encrypted_content" in value:
            return True
        provenance = value.get("provenance")
        if provenance in {"memory_recall", "injected_memory"}:
            return True
        return any(_contains_forbidden_context(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_context(item) for item in value)
    return False


def _looks_injected(text: str) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in INJECTION_MARKERS)


def _ephemeral_tool_noise(text: str) -> bool:
    normalized = " ".join(text.strip().split())
    return any(pattern.fullmatch(normalized) for pattern in EPHEMERAL_TOOL_NOISE)
