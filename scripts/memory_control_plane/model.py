from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


SCHEMA_VERSION = 1
NORMALIZATION_VERSION = 1
MAX_DRAFT_BYTES = 256 * 1024
MAX_CANDIDATE_CANONICAL_BYTES = 300 * 1024
MAX_SOURCE_REFS = 32
MAX_SOURCE_REF_BYTES = 4096
MAX_SOURCE_REVISION_BYTES = 1024

REQUIRED_CANDIDATE_FIELDS = frozenset(
    {
        "schema_version",
        "normalization_version",
        "operation",
        "destination",
        "draft_write",
        "scope",
        "applies_to",
        "owner",
        "source_refs",
        "source_revision",
        "valid_from",
        "valid_to",
        "sensitivity",
    }
)

REQUIRED_GATE_FIELDS = frozenset(
    {
        "prompt_injection",
        "executable_payload",
        "provenance",
        "scope",
        "stability",
        "high_stakes",
        "authority_conflict",
    }
)

SCORE_DIMENSIONS = (
    "recurrence",
    "transferability",
    "stability",
    "impact",
    "contamination_risk",
)

ALLOWED_SCOPES = frozenset({"global", "runtime", "platform", "repo", "learning"})
ALLOWED_APPLIES_TO = frozenset({"all", "codex", "claude_code", "openclaw"})
ALLOWED_SENSITIVITIES = frozenset({"work", "public", "private", "secret", "credential"})
HONEST_CLIENT_SOURCE_KINDS = frozenset(
    {"conversation_turn", "external_evidence", "tool_call", "tool_result"}
)
SUPPORTED_OPERATIONS = frozenset({"add", "update", "no_op", "tombstone"})
DENIED_ROOTS = frozenset(
    {
        ".git",
        "work_contexts",
        "personal_knowledge",
        "personal_memories",
        "memory-sidecar",
        "sessions",
        "browser-state",
        "state",
    }
)

SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{8,}"
    ),
)

PROMPT_INJECTION_PATTERNS = (
    re.compile(r"(?i)\bignore (?:all |any )?(?:previous|prior|above) instructions\b"),
    re.compile(r"(?i)\bsystem prompt\b"),
    re.compile(r"(?i)\bdeveloper message\b"),
    re.compile(r"(?i)\bdo not reveal\b.{0,40}\bprompt\b"),
)

HIDDEN_CONTROL_CODEPOINTS = frozenset(
    {
        0x200B,
        0x200C,
        0x200D,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2060,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
        0xFEFF,
    }
)


class ControlPlaneError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ValidatorSpec:
    name: str
    argv: Tuple[str, ...]
    timeout_seconds: int = 30
    max_output_bytes: int = 32768

    def __post_init__(self) -> None:
        if not self.name or not self.argv:
            raise ValueError("validator name and argv are required")
        if self.timeout_seconds <= 0 or self.max_output_bytes <= 0:
            raise ValueError("validator limits must be positive")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_object(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def safe_rejection_id(reason_codes: Sequence[str], operation: object) -> str:
    safe_shape = {
        "schema_version": SCHEMA_VERSION,
        "operation": operation if operation in {"add", "update", "delete", "no_op", "tombstone"} else "unknown",
        "reason_codes": sorted(set(reason_codes)),
    }
    return "rej_" + digest_object(safe_shape)[:24]


def contains_secret(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in SECRET_PATTERNS)


def contains_hidden_control(value: str) -> bool:
    return any(ord(character) in HIDDEN_CONTROL_CODEPOINTS for character in value)


def contains_prompt_injection(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in PROMPT_INJECTION_PATTERNS)


def normalize_destination(value: object, allowed_subtrees: Sequence[str]) -> Tuple[Optional[str], List[str]]:
    reasons: List[str] = []
    if not isinstance(value, str) or not value:
        return None, ["path_invalid"]
    if value != unicodedata.normalize("NFC", value):
        reasons.append("path_invalid")
    if "\\" in value or "\x00" in value or any(ord(character) < 32 for character in value):
        reasons.append("path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        reasons.append("path_invalid")
    if not path.parts:
        reasons.append("path_invalid")
    elif path.parts[0] in DENIED_ROOTS:
        reasons.append("destination_denied")
    elif path.parts[0] not in set(allowed_subtrees):
        reasons.append("destination_denied")
    if reasons:
        return None, sorted(set(reasons))
    return path.as_posix(), []


def validate_candidate_shape(payload: Mapping[str, Any]) -> List[str]:
    reasons: List[str] = []
    keys = set(payload)
    if keys != REQUIRED_CANDIDATE_FIELDS:
        reasons.append("schema_invalid")
    if payload.get("schema_version") != SCHEMA_VERSION:
        reasons.append("schema_invalid")
    if payload.get("normalization_version") != NORMALIZATION_VERSION:
        reasons.append("schema_invalid")
    if payload.get("scope") not in ALLOWED_SCOPES:
        reasons.append("scope_mismatch")
    if payload.get("applies_to") not in ALLOWED_APPLIES_TO:
        reasons.append("scope_mismatch")
    sensitivity = payload.get("sensitivity")
    if not isinstance(sensitivity, str) or sensitivity not in ALLOWED_SENSITIVITIES:
        reasons.append("schema_invalid")
    owner = payload.get("owner")
    if not isinstance(owner, str) or not owner.strip() or len(owner.encode("utf-8", "ignore")) > 256:
        reasons.append("schema_invalid")
    draft = payload.get("draft_write")
    if not isinstance(draft, str):
        reasons.append("schema_invalid")
    elif len(draft.encode("utf-8")) > MAX_DRAFT_BYTES:
        reasons.append("payload_too_large")
    source_revision = payload.get("source_revision")
    if (
        not isinstance(source_revision, str)
        or not source_revision
        or len(source_revision.encode("utf-8", "ignore")) > MAX_SOURCE_REVISION_BYTES
    ):
        reasons.append("provenance_missing")
    source_refs = payload.get("source_refs")
    if not isinstance(source_refs, list) or not source_refs:
        reasons.append("provenance_missing")
    elif len(source_refs) > MAX_SOURCE_REFS:
        reasons.append("provenance_invalid")
    else:
        for reference in source_refs:
            if not isinstance(reference, dict):
                reasons.append("provenance_invalid")
                continue
            if set(reference) != {"kind", "ref", "sha256"}:
                reasons.append("provenance_invalid")
                continue
            digest = reference.get("sha256")
            locator = reference.get("ref")
            if (
                not isinstance(locator, str)
                or not locator
                or len(locator.encode("utf-8", "ignore")) > MAX_SOURCE_REF_BYTES
            ):
                reasons.append("provenance_invalid")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                reasons.append("provenance_invalid")
    for field in ("valid_from", "valid_to"):
        if payload.get(field) is not None and not isinstance(payload.get(field), str):
            reasons.append("schema_invalid")
    reasons.extend(temporal_window_reasons(payload))
    return sorted(set(reasons))


def _parse_timestamp(value: object) -> Optional[datetime]:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty RFC 3339 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def temporal_window_reasons(
    payload: Mapping[str, Any],
    *,
    at: Optional[datetime] = None,
) -> List[str]:
    try:
        valid_from = _parse_timestamp(payload.get("valid_from"))
        valid_to = _parse_timestamp(payload.get("valid_to"))
    except (TypeError, ValueError, OverflowError):
        return ["temporal_window_invalid"]
    if valid_from is not None and valid_to is not None and valid_from >= valid_to:
        return ["temporal_window_invalid"]
    if at is None:
        return []
    current = at.astimezone(timezone.utc)
    if valid_from is not None and current < valid_from:
        return ["candidate_not_yet_valid"]
    if valid_to is not None and current >= valid_to:
        return ["candidate_expired"]
    return []


def evaluate_gate_evidence(gates: Mapping[str, Any]) -> Tuple[List[Dict[str, str]], List[str], bool]:
    results: List[Dict[str, str]] = []
    reasons: List[str] = []
    keys = set(gates)
    if keys != REQUIRED_GATE_FIELDS:
        reasons.append("gate_unknown")
    for name in sorted(REQUIRED_GATE_FIELDS):
        status = gates.get(name, "unknown")
        if status not in {"pass", "fail", "unknown", "needs_confirmation"}:
            status = "unknown"
        results.append({"gate": name, "status": status})
        if status == "unknown":
            reasons.append("gate_unknown")
        elif status == "needs_confirmation":
            reasons.append("consent_required")
        elif status == "fail":
            reasons.append(
                {
                    "prompt_injection": "prompt_injection_detected",
                    "executable_payload": "executable_payload_disallowed",
                    "provenance": "provenance_invalid",
                    "scope": "scope_mismatch",
                    "stability": "unstable_signal",
                    "high_stakes": "high_stakes_unvalidated",
                    "authority_conflict": "authority_conflict",
                }[name]
            )
    may_score = not reasons
    return results, sorted(set(reasons)), may_score


def validate_assessment(value: Mapping[str, Any]) -> Dict[str, Any]:
    if set(value) != {"scores", "deduplication", "conflict"}:
        raise ControlPlaneError("assessment_invalid", "assessment shape is invalid")
    scores = value.get("scores")
    if not isinstance(scores, dict) or set(scores) != set(SCORE_DIMENSIONS):
        raise ControlPlaneError("assessment_invalid", "score dimensions are invalid")
    normalized_scores: Dict[str, int] = {}
    for name in SCORE_DIMENSIONS:
        score = scores.get(name)
        if isinstance(score, bool) or not isinstance(score, int) or score < 0 or score > 2:
            raise ControlPlaneError("assessment_invalid", "scores must be integers from 0 to 2")
        normalized_scores[name] = score
    deduplication = value.get("deduplication")
    conflict = value.get("conflict")
    if deduplication not in {"novel", "duplicate_noop", "update_existing"}:
        raise ControlPlaneError("assessment_invalid", "deduplication result is invalid")
    if conflict not in {"none", "resolved", "unresolved"}:
        raise ControlPlaneError("assessment_invalid", "conflict result is invalid")
    positive_total = sum(
        normalized_scores[name]
        for name in ("recurrence", "transferability", "stability", "impact")
    )
    contamination_risk = normalized_scores["contamination_risk"]
    effective_total = positive_total + (2 - contamination_risk)
    return {
        "scores": normalized_scores,
        "positive_total": positive_total,
        "contamination_risk": contamination_risk,
        "effective_total": effective_total,
        # Compatibility alias for existing receipt consumers.
        "total": effective_total,
        "deduplication": deduplication,
        "conflict": conflict,
        "eligible": effective_total >= 5
        and deduplication != "duplicate_noop"
        and conflict != "unresolved",
    }


def candidate_set_digest(candidate_hashes: Iterable[str]) -> str:
    values = sorted(set(candidate_hashes))
    return digest_object(
        {
            "schema_version": SCHEMA_VERSION,
            "normalization_version": NORMALIZATION_VERSION,
            "candidate_hashes": values,
        }
    )
