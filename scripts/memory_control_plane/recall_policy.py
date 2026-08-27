"""Versioned, fail-closed policy for every durable memory recall seam."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence


RECALL_POLICY_SCHEMA_VERSION = 1
MAX_RECALL_POLICY_BYTES = 64 * 1024
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "scopes",
        "applies_to",
        "as_of",
        "allowed_authorization_states",
        "allowed_provenance_trust",
        "allowed_privacy_classes",
        "high_stakes",
        "private_profile",
        "eligible_lifecycles",
        "require_source_revision_match",
        "require_content_hash_match",
        "require_canonical_relevance",
        "exclude_tombstoned",
        "exclude_deleted",
    }
)
_PLATFORMS = frozenset({"all", "codex", "claude_code", "openclaw"})
_AUTHORIZATION_STATES = frozenset({"not_required", "user_approved"})
_PROVENANCE_TRUST = frozenset(
    {"canonical_legacy", "current_source_validated", "source_bound_candidate"}
)
_PRIVACY_CLASSES = frozenset({"public", "private_local"})
_FIXED_LIFECYCLES = ("active", "legacy")
_REPO_SCOPE = re.compile(r"^repo:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RECALL_ENTRY_POINTS = frozenset(
    {"agent_cli", "durable_access", "hybrid_retrieval", "native_hook", "projection_cli"}
)
_ROUTER_STAGES = frozenset(
    {"collection_root", "collection_selection", "context_selection", "privacy_boundary"}
)
_HIGH_STAKES_QUERY = re.compile(
    r"\b(?:medical|diagnos(?:is|e)|legal|lawsuit|financial|investment|tax)\b|"
    r"医疗|诊断|法律|诉讼|财务|投资|税务",
    re.IGNORECASE,
)
_RETIRED_QUERY = re.compile(
    r"\b(?:retired|deleted|tombstoned|obsolete)\s+(?:memory|rule|record)\b|"
    r"已删除(?:记忆|规则)|已废弃(?:记忆|规则)|墓碑(?:记忆|规则)",
    re.IGNORECASE,
)


class RecallPolicyError(ValueError):
    """The supplied policy cannot authorize recall."""


def _digest_mapping(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _utc_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise RecallPolicyError("as_of must be a non-empty RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RecallPolicyError("as_of is invalid") from error
    if parsed.tzinfo is None:
        raise RecallPolicyError("as_of must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _enum_list(value: object, *, field: str, allowed: frozenset[str]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise RecallPolicyError("{} must be a non-empty list".format(field))
    if any(not isinstance(item, str) or not item for item in value):
        raise RecallPolicyError("{} contains an invalid value".format(field))
    result = tuple(value)
    if len(set(result)) != len(result) or not set(result).issubset(allowed):
        raise RecallPolicyError("{} contains an unsupported value".format(field))
    return result


@dataclass(frozen=True)
class RecallPolicy:
    """Validated policy value; construction from external data is strict."""

    schema_version: int
    scopes: tuple[str, ...]
    applies_to: str
    as_of: datetime
    allowed_authorization_states: tuple[str, ...]
    allowed_provenance_trust: tuple[str, ...]
    allowed_privacy_classes: tuple[str, ...]
    high_stakes: bool
    private_profile: bool
    eligible_lifecycles: tuple[str, ...] = _FIXED_LIFECYCLES
    require_source_revision_match: bool = True
    require_content_hash_match: bool = True
    require_canonical_relevance: bool = True
    exclude_tombstoned: bool = True
    exclude_deleted: bool = True

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "RecallPolicy":
        if not isinstance(value, Mapping) or set(value) != _POLICY_FIELDS:
            raise RecallPolicyError("recall policy has an invalid field set")
        version = value.get("schema_version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise RecallPolicyError("schema_version must be an integer")
        if version != RECALL_POLICY_SCHEMA_VERSION:
            raise RecallPolicyError("recall policy version is unsupported")
        raw_scopes = value.get("scopes")
        if not isinstance(raw_scopes, list) or not raw_scopes:
            raise RecallPolicyError("scopes must be a non-empty list")
        scopes = tuple(raw_scopes)
        if (
            any(not isinstance(scope, str) or not scope for scope in scopes)
            or len(set(scopes)) != len(scopes)
            or any(
                scope not in {"global", "platform", "learning"}
                and _REPO_SCOPE.fullmatch(scope) is None
                for scope in scopes
            )
        ):
            raise RecallPolicyError("scopes contains an unsupported value")
        applies_to = value.get("applies_to")
        if not isinstance(applies_to, str) or applies_to not in _PLATFORMS:
            raise RecallPolicyError("applies_to is unsupported")
        for field in (
            "high_stakes",
            "private_profile",
            "require_source_revision_match",
            "require_content_hash_match",
            "require_canonical_relevance",
            "exclude_tombstoned",
            "exclude_deleted",
        ):
            if not isinstance(value.get(field), bool):
                raise RecallPolicyError("{} must be boolean".format(field))
        for field in (
            "require_source_revision_match",
            "require_content_hash_match",
            "require_canonical_relevance",
            "exclude_tombstoned",
            "exclude_deleted",
        ):
            if value[field] is not True:
                raise RecallPolicyError("{} cannot be disabled".format(field))
        lifecycles = _enum_list(
            value.get("eligible_lifecycles"),
            field="eligible_lifecycles",
            allowed=frozenset(_FIXED_LIFECYCLES),
        )
        if lifecycles != _FIXED_LIFECYCLES:
            raise RecallPolicyError("eligible_lifecycles cannot be widened or narrowed")
        authorization = _enum_list(
            value.get("allowed_authorization_states"),
            field="allowed_authorization_states",
            allowed=_AUTHORIZATION_STATES,
        )
        provenance = _enum_list(
            value.get("allowed_provenance_trust"),
            field="allowed_provenance_trust",
            allowed=_PROVENANCE_TRUST,
        )
        privacy = _enum_list(
            value.get("allowed_privacy_classes"),
            field="allowed_privacy_classes",
            allowed=_PRIVACY_CLASSES,
        )
        if value["high_stakes"] is True and authorization != ("user_approved",):
            raise RecallPolicyError("high_stakes requires user_approved only")
        if "private_local" in privacy and (
            value["private_profile"] is not True
            or authorization != ("user_approved",)
        ):
            raise RecallPolicyError(
                "private_local requires an explicit private_profile policy "
                "authorized only for user_approved memory"
            )
        return cls(
            schema_version=version,
            scopes=scopes,
            applies_to=applies_to,
            as_of=_utc_time(value.get("as_of")),
            allowed_authorization_states=authorization,
            allowed_provenance_trust=provenance,
            allowed_privacy_classes=privacy,
            high_stakes=value["high_stakes"],
            private_profile=value["private_profile"],
        )

    @classmethod
    def public(
        cls,
        *,
        scopes: Sequence[str],
        applies_to: str,
        high_stakes: bool = False,
        private_profile: bool = False,
        as_of: datetime | None = None,
    ) -> "RecallPolicy":
        instant = as_of or datetime.now(timezone.utc)
        if instant.tzinfo is None:
            raise RecallPolicyError("as_of must be timezone-aware")
        authorization = ["user_approved"] if high_stakes else ["not_required", "user_approved"]
        return cls.from_mapping(
            {
                "schema_version": RECALL_POLICY_SCHEMA_VERSION,
                "scopes": list(scopes),
                "applies_to": applies_to,
                "as_of": instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "allowed_authorization_states": authorization,
                "allowed_provenance_trust": ["canonical_legacy", "current_source_validated"],
                "allowed_privacy_classes": ["public"],
                "high_stakes": high_stakes,
                "private_profile": private_profile,
                "eligible_lifecycles": list(_FIXED_LIFECYCLES),
                "require_source_revision_match": True,
                "require_content_hash_match": True,
                "require_canonical_relevance": True,
                "exclude_tombstoned": True,
                "exclude_deleted": True,
            }
        )

    @classmethod
    def local_work(cls, *, as_of: datetime | None = None) -> "RecallPolicy":
        """Return the built-in policy for explicitly approved local work memory.

        Canonical legacy documents keep their existing progressive-disclosure
        path.  This profile intentionally opens the native recall seam only to
        source-bound or current-source-validated work memory that was approved
        for local use; it does not reinterpret legacy private authority as
        implicitly approved.
        """

        instant = as_of or datetime.now(timezone.utc)
        if instant.tzinfo is None:
            raise RecallPolicyError("as_of must be timezone-aware")
        return cls.from_mapping(
            {
                "schema_version": RECALL_POLICY_SCHEMA_VERSION,
                "scopes": ["global", "platform", "learning"],
                "applies_to": "codex",
                "as_of": instant.astimezone(timezone.utc).isoformat().replace(
                    "+00:00", "Z"
                ),
                "allowed_authorization_states": ["user_approved"],
                "allowed_provenance_trust": [
                    "current_source_validated",
                    "source_bound_candidate",
                ],
                "allowed_privacy_classes": ["public", "private_local"],
                "high_stakes": False,
                "private_profile": True,
                "eligible_lifecycles": list(_FIXED_LIFECYCLES),
                "require_source_revision_match": True,
                "require_content_hash_match": True,
                "require_canonical_relevance": True,
                "exclude_tombstoned": True,
                "exclude_deleted": True,
            }
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scopes": list(self.scopes),
            "applies_to": self.applies_to,
            "as_of": self.as_of.isoformat().replace("+00:00", "Z"),
            "allowed_authorization_states": list(self.allowed_authorization_states),
            "allowed_provenance_trust": list(self.allowed_provenance_trust),
            "allowed_privacy_classes": list(self.allowed_privacy_classes),
            "high_stakes": self.high_stakes,
            "private_profile": self.private_profile,
            "eligible_lifecycles": list(self.eligible_lifecycles),
            "require_source_revision_match": self.require_source_revision_match,
            "require_content_hash_match": self.require_content_hash_match,
            "require_canonical_relevance": self.require_canonical_relevance,
            "exclude_tombstoned": self.exclude_tombstoned,
            "exclude_deleted": self.exclude_deleted,
        }

    def enforce_private_boundary(self, private_profile: bool) -> "RecallPolicy":
        if private_profile and not self.private_profile:
            raise RecallPolicyError(
                "private-profile recall requires explicit policy authorization"
            )
        return self

    def enforce_query_classification(
        self, *, private_profile: bool, high_stakes: bool
    ) -> "RecallPolicy":
        value = self.to_mapping()
        if private_profile and not self.private_profile:
            raise RecallPolicyError(
                "private-profile recall requires explicit policy authorization"
            )
        if high_stakes:
            value["high_stakes"] = True
            value["allowed_authorization_states"] = ["user_approved"]
        return RecallPolicy.from_mapping(value)

    def digest(self) -> str:
        return _digest_mapping(self.to_mapping())


@dataclass(frozen=True)
class VerifiedRecallRequest:
    policy: RecallPolicy
    entry_point: str
    classification: str
    query_sha256: str
    session_sha256: str
    recall_policy_sha256: str
    router_authority_sha256: str
    binding_sha256: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "entry_point": self.entry_point,
            "classification": self.classification,
            "query_sha256": self.query_sha256,
            "session_sha256": self.session_sha256,
            "recall_policy_sha256": self.recall_policy_sha256,
            "router_authority_sha256": self.router_authority_sha256,
            "binding_sha256": self.binding_sha256,
        }


def _router_authority_sha256(route_result: Mapping[str, Any]) -> str:
    value = route_result.get("authority_binding")
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "parent_revision",
        "registry_sha256",
        "source_count",
        "source_set_sha256",
        "binding_sha256",
    }:
        raise RecallPolicyError("router authority binding is unavailable")
    if value.get("schema_version") != 1:
        raise RecallPolicyError("router authority binding version is invalid")
    parent_revision = value.get("parent_revision")
    registry_sha256 = value.get("registry_sha256")
    if parent_revision is not None and (
        not isinstance(parent_revision, str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", parent_revision) is None
    ):
        raise RecallPolicyError("router parent revision is invalid")
    if registry_sha256 is not None and (
        not isinstance(registry_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", registry_sha256) is None
    ):
        raise RecallPolicyError("router registry digest is invalid")
    if (parent_revision is None) != (registry_sha256 is None):
        raise RecallPolicyError("router authority root binding is incomplete")
    source_count = value.get("source_count")
    source_set_sha256 = value.get("source_set_sha256")
    if (
        not isinstance(source_count, int)
        or isinstance(source_count, bool)
        or not 0 <= source_count <= 10_000
        or not isinstance(source_set_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", source_set_sha256) is None
    ):
        raise RecallPolicyError("router authority source binding is invalid")
    digest = value.get("binding_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RecallPolicyError("router authority digest is invalid")
    body = {key: value[key] for key in value if key != "binding_sha256"}
    if _digest_mapping(body) != digest:
        raise RecallPolicyError("router authority binding digest mismatch")
    return digest


def verify_recall_request(
    query: object,
    policy: object,
    *,
    route_result: object,
    entry_point: str,
    session_id: str,
) -> VerifiedRecallRequest:
    """Bind a strict policy to one router-classified production request."""

    if not isinstance(query, str) or not query.strip() or "\x00" in query:
        raise RecallPolicyError("recall query is invalid")
    if entry_point not in _RECALL_ENTRY_POINTS:
        raise RecallPolicyError("recall entry point is invalid")
    if not isinstance(session_id, str) or not session_id or "\x00" in session_id:
        raise RecallPolicyError("recall session binding is invalid")
    if not isinstance(route_result, Mapping):
        raise RecallPolicyError("recall query classification is unavailable")
    trace = route_result.get("trace")
    stage = trace.get("stage") if isinstance(trace, Mapping) else None
    if stage not in _ROUTER_STAGES:
        raise RecallPolicyError("recall query classification is invalid")
    expected_fingerprint = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
    if route_result.get("query_fingerprint") != expected_fingerprint:
        raise RecallPolicyError("recall query classification does not bind the exact query")
    router_authority_sha256 = _router_authority_sha256(route_result)

    private_profile = stage == "privacy_boundary"
    high_stakes = _HIGH_STAKES_QUERY.search(query) is not None
    retired = _RETIRED_QUERY.search(query) is not None
    classification = (
        "retired_memory"
        if retired
        else "private_profile"
        if private_profile
        else "high_stakes"
        if high_stakes
        else "ordinary"
    )
    if retired:
        raise RecallPolicyError("retired memory queries must abstain")
    bound_policy = parse_recall_policy(policy).enforce_query_classification(
        private_profile=private_profile,
        high_stakes=high_stakes,
    )
    body = {
        "schema_version": 2,
        "entry_point": entry_point,
        "classification": classification,
        "query_sha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "session_sha256": hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
        "recall_policy_sha256": bound_policy.digest(),
        "router_authority_sha256": router_authority_sha256,
    }
    return VerifiedRecallRequest(
        policy=bound_policy,
        entry_point=entry_point,
        classification=classification,
        query_sha256=str(body["query_sha256"]),
        session_sha256=str(body["session_sha256"]),
        recall_policy_sha256=str(body["recall_policy_sha256"]),
        router_authority_sha256=str(body["router_authority_sha256"]),
        binding_sha256=_digest_mapping(body),
    )


def validate_recall_request_binding(
    value: object,
    *,
    query: str,
    policy: object,
) -> bool:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_version",
        "entry_point",
        "classification",
        "query_sha256",
        "session_sha256",
        "recall_policy_sha256",
        "router_authority_sha256",
        "binding_sha256",
    }:
        return False
    if value.get("schema_version") != 2 or value.get("entry_point") not in _RECALL_ENTRY_POINTS:
        return False
    if value.get("classification") not in {
        "ordinary",
        "private_profile",
        "high_stakes",
    }:
        return False
    digests = (
        value.get("query_sha256"),
        value.get("session_sha256"),
        value.get("recall_policy_sha256"),
        value.get("router_authority_sha256"),
        value.get("binding_sha256"),
    )
    if any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None for item in digests):
        return False
    parsed = parse_recall_policy(policy)
    if value["query_sha256"] != hashlib.sha256(query.encode("utf-8")).hexdigest():
        return False
    if value["recall_policy_sha256"] != parsed.digest():
        return False
    body = {key: value[key] for key in value if key != "binding_sha256"}
    return value["binding_sha256"] == _digest_mapping(body)


def parse_recall_policy(value: object) -> RecallPolicy:
    if isinstance(value, RecallPolicy):
        return RecallPolicy.from_mapping(value.to_mapping())
    if isinstance(value, Mapping):
        return RecallPolicy.from_mapping(value)
    raise RecallPolicyError("recall policy is required")


def load_recall_policy_file(path: Path, *, max_bytes: int = MAX_RECALL_POLICY_BYTES) -> RecallPolicy:
    """Load a policy from a bounded regular file without following symlinks."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.fspath(path), flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RecallPolicyError("recall policy must be a regular file")
        if metadata.st_size > max_bytes:
            raise RecallPolicyError("recall policy exceeds the size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(max_bytes + 1)
        if len(payload) > max_bytes:
            raise RecallPolicyError("recall policy exceeds the size limit")
        return parse_recall_policy(json.loads(payload.decode("utf-8")))
    finally:
        os.close(descriptor)
