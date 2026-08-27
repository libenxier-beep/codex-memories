from __future__ import annotations

import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .model import (
    ALLOWED_SENSITIVITIES,
    ControlPlaneError,
    HONEST_CLIENT_SOURCE_KINDS,
    MAX_CANDIDATE_CANONICAL_BYTES,
    MAX_DRAFT_BYTES,
    MAX_SOURCE_REFS,
    SUPPORTED_OPERATIONS,
    REQUIRED_GATE_FIELDS,
    ValidatorSpec,
    candidate_set_digest,
    canonical_json,
    contains_hidden_control,
    contains_prompt_injection,
    contains_secret,
    digest_object,
    evaluate_gate_evidence,
    normalize_destination,
    safe_rejection_id,
    sha256_bytes,
    temporal_window_reasons,
    validate_assessment,
    validate_candidate_shape,
)
from .repository import RepositoryAdapter
from .storage import make_event, utc_now, verify_event_chain


IDENTIFIER = re.compile(r"^(?:cand|appr)_[0-9a-f]{24,64}$")
TOMBSTONE_APPROVAL_PLACEHOLDER = "__MEMORY_CONTROL_APPROVAL_RECEIPT__"
TOMBSTONE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,511}$")
TOMBSTONE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
HOST_CAPABILITY_IDENTIFIER = re.compile(r"^cap_[0-9a-f]{64}$")


def _tombstone_reasons(payload: Mapping[str, Any]) -> List[str]:
    if payload.get("operation") != "tombstone":
        return []
    destination = payload.get("destination")
    path = PurePosixPath(destination) if isinstance(destination, str) else PurePosixPath(".")
    if (
        len(path.parts) != 3
        or path.parts[:2] != ("lifecycle", "tombstones")
        or path.suffix.lower() != ".json"
    ):
        return ["tombstone_invalid"]
    draft = payload.get("draft_write")
    if not isinstance(draft, str) or draft.count(TOMBSTONE_APPROVAL_PLACEHOLDER) != 1:
        return ["tombstone_invalid"]
    try:
        value = json.loads(draft)
    except (TypeError, json.JSONDecodeError):
        return ["tombstone_invalid"]
    required = {
        "schema_version", "tombstone_id", "item_id", "authority_path",
        "authority_sha256", "reason", "approval_receipt", "created_at",
        "runtime_purge_binding",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("schema_version") != 1:
        return ["tombstone_invalid"]
    authority_path = value.get("authority_path")
    authority = PurePosixPath(authority_path) if isinstance(authority_path, str) else PurePosixPath(".")
    try:
        created = str(value.get("created_at", ""))
        parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
        temporal_valid = parsed.tzinfo is not None
    except ValueError:
        temporal_valid = False
    reason = value.get("reason")
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
            isinstance(item, str) and re.fullmatch(r"cand_[0-9a-f]{64}", item)
            for item in runtime_purge["target_candidate_ids"]
        )
        and isinstance(runtime_purge.get("session_selector_digests"), list)
        and bool(runtime_purge.get("session_selector_digests"))
        and runtime_purge["session_selector_digests"]
        == sorted(set(runtime_purge["session_selector_digests"]))
        and all(
            isinstance(item, str) and TOMBSTONE_SHA256.fullmatch(item)
            for item in runtime_purge["session_selector_digests"]
        )
    )
    valid = (
        isinstance(value.get("tombstone_id"), str)
        and TOMBSTONE_IDENTIFIER.fullmatch(value["tombstone_id"]) is not None
        and isinstance(value.get("item_id"), str)
        and TOMBSTONE_IDENTIFIER.fullmatch(value["item_id"]) is not None
        and isinstance(authority_path, str)
        and not authority.is_absolute()
        and bool(authority.parts)
        and authority.parts[0] in {"core", "platform", "learnings"}
        and authority.suffix.lower() == ".md"
        and all(part not in {"", ".", ".."} for part in authority.parts)
        and isinstance(value.get("authority_sha256"), str)
        and TOMBSTONE_SHA256.fullmatch(value["authority_sha256"]) is not None
        and isinstance(reason, str)
        and 0 < len(reason.encode("utf-8")) <= 4096
        and value.get("approval_receipt") == TOMBSTONE_APPROVAL_PLACEHOLDER
        and temporal_valid
        and runtime_purge_valid
    )
    if not valid:
        return ["tombstone_invalid"]
    references = payload.get("source_refs")
    repository_refs = [
        reference
        for reference in references if isinstance(reference, dict)
        and reference.get("kind") == "repository_file"
    ] if isinstance(references, list) else []
    if not any(
        reference.get("ref") == authority_path
        and reference.get("sha256") == value.get("authority_sha256")
        for reference in repository_refs
    ):
        return ["tombstone_target_unbound"]
    return []


def _seal(value: Mapping[str, Any]) -> Dict[str, Any]:
    sealed = dict(value)
    sealed["artifact_hash"] = digest_object(value)
    return sealed


def _verify_seal(value: Mapping[str, Any], code: str = "ledger_corrupt") -> None:
    supplied = value.get("artifact_hash")
    unhashed = dict(value)
    unhashed.pop("artifact_hash", None)
    if not isinstance(supplied, str) or supplied != digest_object(unhashed):
        noun = "ledger" if code == "ledger_corrupt" else "receipt"
        raise ControlPlaneError(code, "{} artifact hash is invalid".format(noun))


class MemoryControlPlane:
    """Fail-closed local memory candidate and workspace-application control plane.

    Production mutation requires a host-authenticated capability at both approval
    and application time.  Honest-client evidence is available only through an
    explicit test/development seam.  Successful mutations are reported only as
    ``workspace_applied`` and this module does not publish Git commits.
    """

    def __init__(
        self,
        *,
        repository: Path,
        control_root: Path,
        repository_id: str,
        policy_version: str,
        allowed_subtrees: Sequence[str],
        validators: Sequence[ValidatorSpec],
        host_authorization_verifier: Optional[
            Callable[[object, Mapping[str, Any]], Optional[str]]
        ] = None,
        allow_honest_client_authorization: bool = False,
    ) -> None:
        if not repository_id or not policy_version:
            raise ValueError("repository_id and policy_version are required")
        if not allowed_subtrees:
            raise ValueError("at least one allowed subtree is required")
        self.repository = Path(repository)
        self.control_root = Path(control_root)
        self.repository_id = repository_id
        self.policy_version = policy_version
        self.allowed_subtrees = tuple(allowed_subtrees)
        self.validators = tuple(validators)
        self.host_authorization_verifier = host_authorization_verifier
        self.allow_honest_client_authorization = allow_honest_client_authorization
        self.adapter = RepositoryAdapter(self.repository, self.control_root)
        self.repository = self.adapter.root
        self.control_root = self.adapter.control_root

    @property
    def candidates_root(self) -> Path:
        self.adapter.assert_control_artifact_directory_safe("candidates")
        return self.control_root / "candidates"

    @property
    def approvals_root(self) -> Path:
        self.adapter.assert_control_artifact_directory_safe("approvals")
        return self.control_root / "approvals"

    @property
    def intents_root(self) -> Path:
        self.adapter.assert_control_artifact_directory_safe("intents")
        return self.control_root / "intents"

    @property
    def receipts_root(self) -> Path:
        self.adapter.assert_control_artifact_directory_safe("receipts")
        return self.control_root / "receipts"

    def _candidate_path(self, proposal_id: str) -> Path:
        self.adapter.assert_control_root_safe()
        self.adapter.assert_control_artifact_directory_safe("candidates")
        if IDENTIFIER.fullmatch(proposal_id) is None or not proposal_id.startswith("cand_"):
            raise ControlPlaneError("candidate_hash_mismatch", "proposal identifier is invalid")
        return self.candidates_root / (proposal_id + ".md")

    def _approval_path(self, approval_id: str) -> Path:
        self.adapter.assert_control_root_safe()
        self.adapter.assert_control_artifact_directory_safe("approvals")
        if IDENTIFIER.fullmatch(approval_id) is None or not approval_id.startswith("appr_"):
            raise ControlPlaneError("approval_missing", "approval identifier is invalid")
        return self.approvals_root / (approval_id + ".md")

    def _intent_path(self, proposal_id: str) -> Path:
        self.adapter.assert_control_root_safe()
        self.adapter.assert_control_artifact_directory_safe("intents")
        return self.intents_root / (proposal_id + ".md")

    def _receipt_path(self, proposal_id: str) -> Path:
        self.adapter.assert_control_root_safe()
        self.adapter.assert_control_artifact_directory_safe("receipts")
        return self.receipts_root / (proposal_id + ".md")

    def _repository_binding(self) -> Dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "policy_version": self.policy_version,
            "base_revision": self.adapter.base_revision(),
            "branch": self.adapter.branch(),
            "worktree_identity": self.adapter.worktree_identity(),
            "tracked_workspace_digest": self.adapter.tracked_workspace_digest(),
        }

    def _verify_source_refs(self, payload: Mapping[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
        bindings: List[Dict[str, Any]] = []
        reasons: List[str] = []
        references = payload.get("source_refs")
        if not isinstance(references, list):
            return [], ["provenance_missing"]
        for reference in references:
            if not isinstance(reference, dict):
                reasons.append("provenance_invalid")
                continue
            kind = reference.get("kind")
            locator = reference.get("ref")
            expected = reference.get("sha256")
            if kind == "repository_file" and isinstance(locator, str):
                normalized, path_reasons = normalize_destination(locator, tuple(set(self.allowed_subtrees) | {"evidence"}))
                if path_reasons or normalized is None:
                    reasons.append("provenance_invalid")
                    continue
                path = self.repository / PurePosixPath(normalized)
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    reasons.append("provenance_missing")
                    continue
                if not stat.S_ISREG(info.st_mode) or path.is_symlink():
                    reasons.append("provenance_invalid")
                    continue
                actual = sha256_bytes(path.read_bytes())
                if actual != expected:
                    reasons.append("provenance_invalid")
                    continue
                bindings.append(
                    {
                        "kind": kind,
                        "ref": normalized,
                        "sha256": actual,
                        "verification": "repository_file_reopened",
                    }
                )
            elif kind in HONEST_CLIENT_SOURCE_KINDS:
                if not isinstance(locator, str) or not locator or not isinstance(expected, str):
                    reasons.append("provenance_invalid")
                    continue
                bindings.append(
                    {
                        "kind": kind,
                        "ref": locator,
                        "sha256": expected,
                        "verification": "honest_client_asserted",
                    }
                )
            else:
                reasons.append("provenance_invalid")
        return bindings, sorted(set(reasons))

    def _pre_persistence_rejection(
        self,
        payload: Mapping[str, Any],
        gate_evidence: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        reasons: List[str] = []
        try:
            in_memory_bytes = canonical_json({"payload": payload, "gate_evidence": gate_evidence})
            in_memory_text = in_memory_bytes.decode("utf-8")
            if len(in_memory_bytes) > MAX_CANDIDATE_CANONICAL_BYTES:
                reasons.append("payload_too_large")
        except (TypeError, ValueError, UnicodeError):
            in_memory_text = ""
            reasons.append("schema_invalid")
        draft = payload.get("draft_write") if isinstance(payload, Mapping) else None
        if contains_secret(in_memory_text):
            reasons.append("secret_detected")
        sensitivity = payload.get("sensitivity")
        if not isinstance(sensitivity, str) or sensitivity not in ALLOWED_SENSITIVITIES:
            reasons.append("schema_invalid")
        elif sensitivity in {"private", "secret", "credential"}:
            reasons.append("disallowed_personal_data")
        source_refs = payload.get("source_refs")
        if isinstance(source_refs, list) and len(source_refs) > MAX_SOURCE_REFS:
            reasons.append("provenance_invalid")
        if isinstance(draft, str):
            try:
                if len(draft.encode("utf-8")) > MAX_DRAFT_BYTES:
                    reasons.append("payload_too_large")
            except UnicodeEncodeError:
                reasons.append("schema_invalid")
            if contains_hidden_control(draft):
                reasons.append("hidden_control_text")
            if contains_prompt_injection(draft):
                reasons.append("prompt_injection_detected")
            if re.search(r"(?is)(?:^|\n)#!\s*/|\bcurl\b.{0,100}\|\s*(?:sh|bash)\b|\brm\s+-rf\b", draft):
                reasons.append("executable_payload_disallowed")
        if not reasons:
            return None
        return {
            "schema_version": 1,
            "proposal_id": safe_rejection_id(reasons, payload.get("operation")),
            "candidate_hash": None,
            "candidate_set_digest": None,
            "disposition": "rejected",
            "may_score": False,
            "gate_results": [],
            "reason_codes": sorted(set(reasons)),
            "persisted": False,
        }

    def _gate_rejection_before_persistence(
        self,
        payload: Mapping[str, Any],
        gate_results: Sequence[Mapping[str, str]],
        gate_reasons: Sequence[str],
    ) -> Optional[Dict[str, Any]]:
        unsafe_reasons = sorted(
            set(gate_reasons)
            & {"prompt_injection_detected", "executable_payload_disallowed"}
        )
        if not unsafe_reasons:
            return None
        return {
            "schema_version": 1,
            "proposal_id": safe_rejection_id(unsafe_reasons, payload.get("operation")),
            "candidate_hash": None,
            "candidate_set_digest": None,
            "disposition": "rejected",
            "may_score": False,
            "gate_results": list(gate_results),
            "reason_codes": unsafe_reasons,
            "persisted": False,
        }

    def prepare(self, payload: Mapping[str, Any], gate_evidence: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(payload, Mapping) or not isinstance(gate_evidence, Mapping):
            return {
                "schema_version": 1,
                "proposal_id": "rej_" + "0" * 24,
                "candidate_hash": None,
                "candidate_set_digest": None,
                "disposition": "rejected",
                "may_score": False,
                "gate_results": [],
                "reason_codes": ["schema_invalid"],
                "persisted": False,
            }
        unsafe = self._pre_persistence_rejection(payload, gate_evidence)
        if unsafe is not None:
            return unsafe
        reasons = validate_candidate_shape(payload)
        normalized_destination, destination_reasons = normalize_destination(
            payload.get("destination"), self.allowed_subtrees
        )
        reasons.extend(destination_reasons)
        operation = payload.get("operation")
        if operation not in SUPPORTED_OPERATIONS:
            reasons.append("unsupported_operation")
        reasons.extend(_tombstone_reasons(payload))

        gate_results, gate_reasons, may_score = evaluate_gate_evidence(gate_evidence)
        unsafe_gate = self._gate_rejection_before_persistence(payload, gate_results, gate_reasons)
        reasons.extend(gate_reasons)

        if isinstance(payload.get("draft_write"), str):
            if payload.get("scope") == "global" and normalized_destination is not None:
                if PurePosixPath(normalized_destination).parts[0] not in {"core", "learnings", "lifecycle"}:
                    reasons.append("scope_mismatch")
            if payload.get("scope") == "platform" and normalized_destination is not None:
                if PurePosixPath(normalized_destination).parts[0] not in {"platform", "lifecycle"}:
                    reasons.append("scope_mismatch")
            if payload.get("scope") in {"repo", "runtime"}:
                reasons.append("scope_mismatch")

        source_bindings, provenance_reasons = self._verify_source_refs(payload)
        reasons.extend(provenance_reasons)

        target_precondition: Optional[Dict[str, Any]] = None
        if normalized_destination is not None and operation in SUPPORTED_OPERATIONS:
            destination_root = PurePosixPath(normalized_destination).parts[0]
            if destination_root == "lifecycle" and operation != "tombstone":
                reasons.append("destination_denied")
            if operation == "tombstone" and destination_root != "lifecycle":
                reasons.append("tombstone_invalid")
            target_precondition, target_reasons = self.adapter.target_precondition(
                normalized_destination, str(operation)
            )
            reasons.extend(target_reasons)

        if normalized_destination is not None and target_precondition is not None:
            try:
                self.adapter.assert_publishable_authority_state(self.allowed_subtrees)
            except ControlPlaneError as error:
                unpublished_reasons = [error.code]
                return {
                    "schema_version": 1,
                    "proposal_id": safe_rejection_id(unpublished_reasons, operation),
                    "candidate_hash": None,
                    "candidate_set_digest": None,
                    "disposition": "rejected",
                    "may_score": False,
                    "gate_results": gate_results,
                    "reason_codes": unpublished_reasons,
                    "persisted": False,
                }

        reasons = sorted(set(reasons))
        may_score = may_score and not reasons
        if reasons:
            disposition = "needs_confirmation" if set(reasons) <= {"consent_required"} else "rejected"
        else:
            disposition = "quarantined"

        if normalized_destination is None or target_precondition is None:
            return {
                "schema_version": 1,
                "proposal_id": safe_rejection_id(reasons or ["schema_invalid"], operation),
                "candidate_hash": None,
                "candidate_set_digest": None,
                "disposition": "rejected",
                "may_score": False,
                "gate_results": gate_results,
                "reason_codes": reasons or ["schema_invalid"],
                "persisted": False,
            }

        normalized_payload = dict(payload)
        normalized_payload["destination"] = normalized_destination
        repository_binding = self._repository_binding()
        identity = {
            "schema_version": 1,
            "normalization_version": 1,
            "repository": repository_binding,
            "payload": normalized_payload,
            "source_bindings": source_bindings,
            "target_precondition": target_precondition,
        }
        candidate_hash = digest_object(identity)
        proposal_id = "cand_" + candidate_hash
        set_digest = candidate_set_digest([candidate_hash])
        path = self._candidate_path(proposal_id)
        with self.adapter.writer_lock():
            if self.adapter.control_artifact_exists("candidates", path.name):
                ledger = self._load_candidate(proposal_id)
                if ledger.get("identity_redacted") is True:
                    return self._redacted_rejection_receipt(ledger)
                if reasons:
                    updated = dict(ledger)
                    updated["gate_results"] = gate_results
                    updated["may_score"] = False
                    updated["disposition"] = (
                        "needs_confirmation"
                        if set(reasons) <= {"consent_required"}
                        else "rejected"
                    )
                    updated["reason_codes"] = sorted(
                        set(updated.get("reason_codes", [])) | set(reasons)
                    )
                    events = list(updated["events"])
                    events.append(
                        make_event(
                            "gate_rejected",
                            {
                                "disposition": updated["disposition"],
                                "may_score": False,
                                "reason_codes": updated["reason_codes"],
                            },
                            events,
                        )
                    )
                    updated["events"] = events
                    self._write_candidate(updated)
                    ledger = self._load_candidate(proposal_id)
                return self._proposal_receipt(ledger)
            if unsafe_gate is not None:
                event = make_event(
                    "gate_rejected",
                    {
                        "disposition": "rejected",
                        "may_score": False,
                        "reason_codes": list(unsafe_gate["reason_codes"]),
                    },
                    [],
                )
                redacted = _seal(
                    {
                        "schema_version": 1,
                        "normalization_version": 1,
                        "proposal_id": proposal_id,
                        "candidate_hash": candidate_hash,
                        "identity_redacted": True,
                        "gate_results": [],
                        "disposition": "rejected",
                        "may_score": False,
                        "reason_codes": list(unsafe_gate["reason_codes"]),
                        "assessment": None,
                        "approval_ids": [],
                        "events": [event],
                    }
                )
                self.adapter.write_control_artifact(
                    "candidates",
                    path.name,
                    "candidate-ledger",
                    redacted,
                )
                return unsafe_gate

            event = make_event(
                "screened",
                {
                    "disposition": disposition,
                    "may_score": may_score,
                    "reason_codes": reasons,
                },
                [],
            )
            ledger = _seal(
                {
                    "schema_version": 1,
                    "normalization_version": 1,
                    "proposal_id": proposal_id,
                    "candidate_hash": candidate_hash,
                    "identity": identity,
                    "gate_results": gate_results,
                    "disposition": disposition,
                    "may_score": may_score,
                    "reason_codes": reasons,
                    "assessment": None,
                    "approval_ids": [],
                    "events": [event],
                }
            )
            self.adapter.write_control_artifact("candidates", path.name, "candidate-ledger", ledger)
            return self._proposal_receipt(ledger)

    def _redacted_rejection_receipt(self, ledger: Mapping[str, Any]) -> Dict[str, Any]:
        reasons = list(ledger.get("reason_codes", []))
        return {
            "schema_version": 1,
            "proposal_id": safe_rejection_id(reasons, None),
            "candidate_hash": None,
            "candidate_set_digest": None,
            "disposition": "rejected",
            "may_score": False,
            "gate_results": [],
            "reason_codes": reasons,
            "persisted": False,
        }

    def _proposal_receipt(self, ledger: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "proposal_id": ledger["proposal_id"],
            "candidate_hash": ledger["candidate_hash"],
            "candidate_set_digest": candidate_set_digest([ledger["candidate_hash"]]),
            "disposition": ledger["disposition"],
            "may_score": ledger["may_score"],
            "gate_results": ledger["gate_results"],
            "reason_codes": ledger["reason_codes"],
            "persisted": True,
            "artifact": self._candidate_path(str(ledger["proposal_id"])).relative_to(self.repository).as_posix(),
        }

    def _load_candidate(self, proposal_id: str) -> Dict[str, Any]:
        path = self._candidate_path(proposal_id)
        if not self.adapter.control_artifact_exists("candidates", path.name):
            raise ControlPlaneError("candidate_missing", "candidate ledger is missing")
        ledger = self.adapter.read_control_artifact("candidates", path.name, "candidate-ledger")
        _verify_seal(ledger)
        verify_event_chain(ledger.get("events"))
        if ledger.get("identity_redacted") is True:
            candidate_hash = ledger.get("candidate_hash")
            if (
                not isinstance(candidate_hash, str)
                or ledger.get("proposal_id") != "cand_" + candidate_hash
                or ledger.get("disposition") != "rejected"
                or ledger.get("may_score") is not False
                or ledger.get("assessment") is not None
                or ledger.get("approval_ids") != []
                or not isinstance(ledger.get("reason_codes"), list)
            ):
                raise ControlPlaneError("ledger_corrupt", "redacted rejection marker is invalid")
            return ledger
        identity = ledger.get("identity")
        if not isinstance(identity, dict):
            raise ControlPlaneError("ledger_corrupt", "candidate identity is invalid")
        expected_hash = digest_object(identity)
        if ledger.get("candidate_hash") != expected_hash or ledger.get("proposal_id") != "cand_" + expected_hash:
            raise ControlPlaneError("ledger_corrupt", "candidate hash does not match immutable identity")
        return ledger

    def _write_candidate(self, ledger: Mapping[str, Any]) -> None:
        value = dict(ledger)
        value.pop("artifact_hash", None)
        path = self._candidate_path(str(value["proposal_id"]))
        self.adapter.write_control_artifact("candidates", path.name, "candidate-ledger", _seal(value))

    def _append_candidate_event(
        self,
        ledger: Dict[str, Any],
        kind: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        events = list(ledger["events"])
        events.append(make_event(kind, data, events))
        ledger = dict(ledger)
        ledger["events"] = events
        self._write_candidate(ledger)
        return self._load_candidate(str(ledger["proposal_id"]))

    def assess(self, proposal_id: str, assessment: Mapping[str, Any]) -> Mapping[str, Any]:
        with self.adapter.writer_lock():
            ledger = self._load_candidate(proposal_id)
            if not ledger.get("may_score"):
                raise ControlPlaneError("invalid_transition", "candidate is not score eligible")
            if ledger.get("assessment") is not None:
                return dict(ledger["assessment"])
            normalized = validate_assessment(assessment)
            normalized["assessed_at"] = utc_now()
            normalized["assessment_hash"] = digest_object(normalized)
            ledger = dict(ledger)
            ledger["assessment"] = normalized
            if not normalized["eligible"]:
                if normalized["conflict"] == "unresolved":
                    ledger["disposition"] = "needs_confirmation"
                    ledger["reason_codes"] = ["unresolved_conflict"]
                else:
                    ledger["disposition"] = "rejected"
                    ledger["reason_codes"] = [
                        "duplicate_noop"
                        if normalized["deduplication"] == "duplicate_noop"
                        else "positive_score_below_threshold"
                    ]
            events = list(ledger["events"])
            events.append(
                make_event(
                    "assessed",
                    {
                        "assessment_hash": normalized["assessment_hash"],
                        "eligible": normalized["eligible"],
                        "disposition": ledger["disposition"],
                    },
                    events,
                )
            )
            ledger["events"] = events
            self._write_candidate(ledger)
            return dict(normalized)

    def candidate_set(self, proposal_ids: Sequence[str]) -> str:
        if not proposal_ids or len(set(proposal_ids)) != len(proposal_ids):
            raise ControlPlaneError("candidate_set_stale", "candidate set must contain unique proposal IDs")
        hashes = [str(self._load_candidate(proposal_id)["candidate_hash"]) for proposal_id in proposal_ids]
        return candidate_set_digest(hashes)

    def _authorization_context(
        self,
        set_digest: str,
        evidence: Mapping[str, Any],
    ) -> Dict[str, Any]:
        required = {"mode", "candidate_ids", "actor_claim", "current_turn_ref"}
        allowed = required | {"except_ids"}
        if set(evidence) < required or set(evidence) - allowed:
            raise ControlPlaneError("approval_missing", "approval evidence is incomplete or unknown")
        mode = evidence.get("mode")
        candidate_ids = evidence.get("candidate_ids")
        actor = evidence.get("actor_claim")
        turn = evidence.get("current_turn_ref")
        if mode not in {"approve_ids", "approve_set_except"}:
            raise ControlPlaneError("approval_missing", "approval mode is invalid")
        if not isinstance(candidate_ids, list) or not candidate_ids or len(set(candidate_ids)) != len(candidate_ids):
            raise ControlPlaneError("candidate_set_stale", "candidate set is invalid")
        if not isinstance(actor, str) or not actor.strip() or not isinstance(turn, str) or not turn.strip():
            raise ControlPlaneError("approval_missing", "explicit current-turn approval evidence is required")
        except_ids = evidence.get("except_ids", [])
        if mode == "approve_ids" and except_ids:
            raise ControlPlaneError("approval_missing", "approve_ids cannot contain exceptions")
        if mode == "approve_set_except":
            if not isinstance(except_ids, list) or not set(except_ids) <= set(candidate_ids):
                raise ControlPlaneError("candidate_set_stale", "approval exceptions are invalid")
        approved_ids = [identifier for identifier in candidate_ids if identifier not in set(except_ids)]
        if not approved_ids:
            raise ControlPlaneError("approval_missing", "approval must approve at least one candidate")
        if len(approved_ids) > 1:
            raise ControlPlaneError(
                "batch_application_unsupported",
                "batch_application_unsupported: V1 approval may authorize only one executable candidate",
            )
        ledgers = [self._load_candidate(str(identifier)) for identifier in candidate_ids]
        actual_set = candidate_set_digest([str(ledger["candidate_hash"]) for ledger in ledgers])
        if actual_set != set_digest:
            raise ControlPlaneError("candidate_set_stale", "candidate set digest is stale")
        snapshots: List[Dict[str, Any]] = []
        for ledger in ledgers:
            if ledger["proposal_id"] in approved_ids:
                assessment = ledger.get("assessment")
                if (
                    not isinstance(assessment, dict)
                    or not assessment.get("eligible")
                    or ledger.get("disposition") == "rejected"
                ):
                    raise ControlPlaneError("invalid_transition", "candidate is not approval eligible")
                snapshots.append(
                    {
                        "proposal_id": ledger["proposal_id"],
                        "candidate_hash": ledger["candidate_hash"],
                        "repository": ledger["identity"]["repository"],
                        "source_revision": ledger["identity"]["payload"]["source_revision"],
                        "operation": ledger["identity"]["payload"]["operation"],
                        "destination": ledger["identity"]["payload"]["destination"],
                        "target_precondition": ledger["identity"]["target_precondition"],
                    }
                )
        authorization_request = {
            "phase": "authorize",
            "candidate_set_digest": set_digest,
            "approved_candidate_ids": sorted(approved_ids),
            "except_ids": sorted(except_ids),
            "actor_claim": actor,
            "current_turn_ref": turn,
            "mode": mode,
            "snapshots": snapshots,
        }
        return {
            "mode": mode,
            "actor": actor,
            "turn": turn,
            "except_ids": except_ids,
            "approved_ids": approved_ids,
            "ledgers": ledgers,
            "snapshots": snapshots,
            "authorization_request": authorization_request,
        }

    def authorization_request(
        self,
        set_digest: str,
        evidence: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Return the exact request an external host must authorize."""

        with self.adapter.writer_lock():
            return dict(
                self._authorization_context(set_digest, evidence)[
                    "authorization_request"
                ]
            )

    def authorize(
        self,
        set_digest: str,
        evidence: Mapping[str, Any],
        *,
        host_capability: object = None,
        failpoint: Optional[str] = None,
    ) -> Mapping[str, Any]:
        with self.adapter.writer_lock():
            context = self._authorization_context(set_digest, evidence)
            mode = context["mode"]
            actor = context["actor"]
            turn = context["turn"]
            except_ids = context["except_ids"]
            approved_ids = context["approved_ids"]
            ledgers = context["ledgers"]
            snapshots = context["snapshots"]
            authorization_request = context["authorization_request"]
            authorization_strength = "honest_client_audit"
            host_authenticated = False
            host_capability_id: Optional[str] = None
            if self.host_authorization_verifier is not None or host_capability is not None:
                if self.host_authorization_verifier is None or host_capability is None:
                    raise ControlPlaneError(
                        "host_authentication_required",
                        "host authentication capability is required",
                    )
                try:
                    verified_id = self.host_authorization_verifier(
                        host_capability, authorization_request
                    )
                except Exception as error:
                    raise ControlPlaneError(
                        "host_authentication_required",
                        "host authentication capability verification failed",
                    ) from error
                if (
                    not isinstance(verified_id, str)
                    or HOST_CAPABILITY_IDENTIFIER.fullmatch(verified_id) is None
                ):
                    raise ControlPlaneError(
                        "host_authentication_required",
                        "host authentication capability verification failed",
                    )
                authorization_strength = "host_authenticated_capability"
                host_authenticated = True
                host_capability_id = verified_id
            elif not self.allow_honest_client_authorization:
                raise ControlPlaneError(
                    "host_authentication_required",
                    "host authentication capability is required",
                )
            approval_key = digest_object(
                {
                    "schema_version": 1,
                    "candidate_set_digest": set_digest,
                    "approved_candidate_ids": sorted(approved_ids),
                    "except_ids": sorted(except_ids),
                    "actor_claim": actor,
                    "current_turn_ref": turn,
                    "mode": mode,
                    "authorization_strength": authorization_strength,
                    "host_authenticated": host_authenticated,
                    "host_capability_id": host_capability_id,
                    "snapshots": snapshots,
                }
            )
            approval_id = "appr_" + approval_key
            path = self._approval_path(approval_id)
            if self.adapter.control_artifact_exists("approvals", path.name):
                approval = self._load_approval(approval_id)
                self._reconcile_approval(approval, ledgers)
                return approval
            for ledger in ledgers:
                if ledger["proposal_id"] in approved_ids and ledger.get("disposition") == "approved":
                    raise ControlPlaneError("invalid_transition", "candidate is already approved elsewhere")
            approval = _seal(
                {
                    "schema_version": 1,
                    "approval_id": approval_id,
                    "candidate_set_digest": set_digest,
                    "approved_candidate_ids": sorted(approved_ids),
                    "except_ids": sorted(except_ids),
                    "actor_claim": actor,
                    "current_turn_ref": turn,
                    "approval_mode": mode,
                    "authorization_strength": authorization_strength,
                    "host_authenticated": host_authenticated,
                    "host_capability_id": host_capability_id,
                    "snapshots": snapshots,
                    "approved_at": utc_now(),
                    "approval_key": approval_key,
                }
            )
            self.adapter.write_control_artifact("approvals", path.name, "approval-receipt", approval)
            if failpoint == "after_approval_artifact":
                raise ControlPlaneError(
                    "failpoint_after_approval_artifact",
                    "failpoint_after_approval_artifact",
                )
            self._reconcile_approval(approval, ledgers)
            return dict(approval)

    def _reconcile_approval(
        self,
        approval: Mapping[str, Any],
        ledgers: Sequence[Mapping[str, Any]],
    ) -> None:
        approval_id = str(approval["approval_id"])
        approved_ids = set(approval["approved_candidate_ids"])
        for original in ledgers:
            if original["proposal_id"] not in approved_ids:
                continue
            ledger = self._load_candidate(str(original["proposal_id"]))
            existing_ids = list(ledger.get("approval_ids", []))
            already_linked = approval_id in existing_ids
            already_evented = any(
                event.get("kind") == "approved"
                and event.get("data", {}).get("approval_id") == approval_id
                for event in ledger["events"]
            )
            if already_linked and already_evented and ledger.get("disposition") == "approved":
                continue
            if existing_ids and not already_linked:
                raise ControlPlaneError("invalid_transition", "candidate is already approved elsewhere")
            updated = dict(ledger)
            updated["disposition"] = "approved"
            updated["approval_ids"] = existing_ids if already_linked else existing_ids + [approval_id]
            if not already_evented:
                events = list(updated["events"])
                events.append(
                    make_event(
                        "approved",
                        {
                            "approval_id": approval_id,
                            "candidate_set_digest": approval["candidate_set_digest"],
                            "authorization_strength": approval["authorization_strength"],
                        },
                        events,
                    )
                )
                updated["events"] = events
            self._write_candidate(updated)

    def _load_approval(self, approval_id: str) -> Dict[str, Any]:
        path = self._approval_path(approval_id)
        if not self.adapter.control_artifact_exists("approvals", path.name):
            raise ControlPlaneError("approval_missing", "approval receipt is missing")
        approval = self.adapter.read_control_artifact("approvals", path.name, "approval-receipt")
        _verify_seal(approval, "receipt_invalid")
        if approval.get("approval_id") != approval_id:
            raise ControlPlaneError("receipt_invalid", "approval identifier is invalid")
        unhashed = {
            "schema_version": approval.get("schema_version"),
            "candidate_set_digest": approval.get("candidate_set_digest"),
            "approved_candidate_ids": approval.get("approved_candidate_ids"),
            "except_ids": approval.get("except_ids"),
            "actor_claim": approval.get("actor_claim"),
            "current_turn_ref": approval.get("current_turn_ref"),
            "mode": approval.get("approval_mode"),
            "authorization_strength": approval.get("authorization_strength"),
            "host_authenticated": approval.get("host_authenticated"),
            "host_capability_id": approval.get("host_capability_id"),
            "snapshots": approval.get("snapshots"),
        }
        if approval.get("approval_key") != digest_object(unhashed):
            raise ControlPlaneError("receipt_invalid", "approval content binding is invalid")
        return approval

    def _assert_approval_authorized(
        self,
        approval: Mapping[str, Any],
        *,
        host_capability: object,
        phase: str,
    ) -> None:
        strength = approval.get("authorization_strength")
        authenticated = approval.get("host_authenticated")
        if strength == "honest_client_audit" and authenticated is False:
            if self.allow_honest_client_authorization:
                return
            raise ControlPlaneError(
                "host_authentication_required",
                "host authentication is required for production application",
            )
        capability_id = approval.get("host_capability_id")
        if (
            strength != "host_authenticated_capability"
            or authenticated is not True
            or not isinstance(capability_id, str)
            or HOST_CAPABILITY_IDENTIFIER.fullmatch(capability_id) is None
            or self.host_authorization_verifier is None
            or host_capability is None
        ):
            raise ControlPlaneError(
                "host_authentication_required",
                "host authentication is required for production application",
            )
        request = {
            "phase": phase,
            "approval_id": approval.get("approval_id"),
            "candidate_set_digest": approval.get("candidate_set_digest"),
            "approved_candidate_ids": approval.get("approved_candidate_ids"),
            "except_ids": approval.get("except_ids"),
            "actor_claim": approval.get("actor_claim"),
            "current_turn_ref": approval.get("current_turn_ref"),
            "mode": approval.get("approval_mode"),
            "snapshots": approval.get("snapshots"),
        }
        try:
            verified_id = self.host_authorization_verifier(host_capability, request)
        except Exception as error:
            raise ControlPlaneError(
                "host_authentication_required",
                "host authentication capability verification failed",
            ) from error
        if verified_id != capability_id:
            raise ControlPlaneError(
                "host_authentication_required",
                "host authentication capability verification failed",
            )

    def _verify_repository_and_sources(self, ledger: Mapping[str, Any]) -> None:
        expected = ledger["identity"]["repository"]
        actual = self._repository_binding()
        for field in (
            "repository_id",
            "policy_version",
            "base_revision",
            "branch",
            "worktree_identity",
        ):
            if expected.get(field) != actual.get(field):
                code = "source_revision_stale" if field == "base_revision" else "workspace_revision_stale"
                raise ControlPlaneError(code, "repository binding is stale: {}".format(field))
        payload = ledger["identity"]["payload"]
        current_sources, reasons = self._verify_source_refs(payload)
        if reasons or current_sources != ledger["identity"]["source_bindings"]:
            raise ControlPlaneError("source_revision_stale", "source revision is stale")

    def _verify_current_binding(self, ledger: Mapping[str, Any]) -> None:
        self.adapter.assert_publishable_authority_state(self.allowed_subtrees)
        self._verify_repository_and_sources(ledger)
        expected = ledger["identity"]["repository"]
        actual = self._repository_binding()
        payload = ledger["identity"]["payload"]
        expected_target = ledger["identity"]["target_precondition"]
        actual_target, target_reasons = self.adapter.target_precondition(
            payload["destination"], payload["operation"]
        )
        if target_reasons or actual_target is None or not self.adapter.precondition_matches(expected_target, actual_target):
            raise ControlPlaneError("target_precondition_stale", "target precondition is stale")
        if expected.get("tracked_workspace_digest") != actual.get("tracked_workspace_digest"):
            raise ControlPlaneError("workspace_revision_stale", "repository binding is stale: tracked_workspace_digest")

    def _receipt_body(
        self,
        ledger: Mapping[str, Any],
        approval: Mapping[str, Any],
        intent: Mapping[str, Any],
        *,
        recovered: bool,
        completed_at: str,
    ) -> Dict[str, Any]:
        body = {
            "schema_version": 1,
            "proposal_id": ledger["proposal_id"],
            "candidate_hash": ledger["candidate_hash"],
            "approval_id": approval["approval_id"],
            "candidate_set_digest": approval["candidate_set_digest"],
            "repository": ledger["identity"]["repository"],
            "source_revision": ledger["identity"]["payload"]["source_revision"],
            "destination": ledger["identity"]["payload"]["destination"],
            "operation": ledger["identity"]["payload"]["operation"],
            "before": intent["before"],
            "after": intent["after"],
            "validation": intent["validation"],
            "post_workspace_digest": intent["post_workspace_digest"],
            "status": "workspace_applied",
            "git_published": False,
            "committed_reader_visible": False,
            "authorization_strength": approval["authorization_strength"],
            "recovered": recovered,
            "completed_at": completed_at,
        }
        body["receipt_id"] = "workspace_" + digest_object(body)
        return body

    def _write_workspace_receipt(
        self,
        ledger: Mapping[str, Any],
        approval: Mapping[str, Any],
        intent: Mapping[str, Any],
        *,
        recovered: bool,
    ) -> Dict[str, Any]:
        current = self._load_candidate(str(ledger["proposal_id"]))
        body: Optional[Dict[str, Any]] = None
        for event in reversed(current["events"]):
            data = event.get("data", {})
            if (
                event.get("kind") != "workspace_applied"
                or not isinstance(data, dict)
                or data.get("approval_id") != approval.get("approval_id")
                or not isinstance(data.get("completed_at"), str)
                or not isinstance(data.get("recovered"), bool)
            ):
                continue
            candidate = self._receipt_body(
                current,
                approval,
                intent,
                recovered=data["recovered"],
                completed_at=data["completed_at"],
            )
            if candidate["receipt_id"] == data.get("receipt_id"):
                body = candidate
                break
        if body is None:
            completed_at = utc_now()
            body = self._receipt_body(
                current,
                approval,
                intent,
                recovered=recovered,
                completed_at=completed_at,
            )
            current = self._append_candidate_event(
                current,
                "workspace_applied",
                {
                    "receipt_id": body["receipt_id"],
                    "approval_id": body["approval_id"],
                    "after_sha256": body["after"].get("sha256"),
                    "recovered": recovered,
                    "completed_at": completed_at,
                    "git_published": False,
                },
            )
        receipt = _seal(body)
        path = self._receipt_path(str(ledger["proposal_id"]))
        self.adapter.write_control_artifact(
            "receipts",
            path.name,
            "workspace-application-receipt",
            receipt,
        )
        return self._load_workspace_receipt(str(ledger["proposal_id"]))

    def _load_intent(self, proposal_id: str) -> Dict[str, Any]:
        path = self._intent_path(proposal_id)
        if not self.adapter.control_artifact_exists("intents", path.name):
            raise ControlPlaneError("recovery_required", "application intent is missing")
        intent = self.adapter.read_control_artifact(
            "intents",
            path.name,
            "workspace-application-intent",
        )
        _verify_seal(intent, "receipt_invalid")
        if intent.get("proposal_id") != proposal_id:
            raise ControlPlaneError("receipt_invalid", "application intent is mismatched")
        if not isinstance(intent.get("post_workspace_digest"), str):
            raise ControlPlaneError("receipt_invalid", "application intent lacks a post-state binding")
        return intent

    def _load_workspace_receipt(self, proposal_id: str) -> Dict[str, Any]:
        path = self._receipt_path(proposal_id)
        if not self.adapter.control_artifact_exists("receipts", path.name):
            raise ControlPlaneError("receipt_invalid", "workspace receipt is missing")
        receipt = self.adapter.read_control_artifact(
            "receipts",
            path.name,
            "workspace-application-receipt",
        )
        _verify_seal(receipt, "receipt_invalid")
        if receipt.get("proposal_id") != proposal_id:
            raise ControlPlaneError("receipt_invalid", "workspace receipt is mismatched")
        approval_id = receipt.get("approval_id")
        if not isinstance(approval_id, str):
            raise ControlPlaneError("receipt_invalid", "workspace receipt approval is invalid")
        ledger = self._load_candidate(proposal_id)
        matching_events = [
            event
            for event in ledger["events"]
            if event.get("kind") == "workspace_applied"
            and isinstance(event.get("data"), dict)
            and event["data"].get("receipt_id") == receipt.get("receipt_id")
        ]
        if len(matching_events) != 1:
            raise ControlPlaneError("receipt_invalid", "workspace receipt event binding is invalid")
        event_data = matching_events[0]["data"]
        if (
            event_data.get("approval_id") != approval_id
            or not isinstance(event_data.get("completed_at"), str)
            or not isinstance(event_data.get("recovered"), bool)
        ):
            raise ControlPlaneError("receipt_invalid", "workspace receipt issuance evidence is invalid")
        body = self._receipt_body(
            ledger,
            self._load_approval(approval_id),
            self._load_intent(proposal_id),
            recovered=event_data["recovered"],
            completed_at=event_data["completed_at"],
        )
        if _seal(body) != receipt:
            raise ControlPlaneError("receipt_invalid", "workspace receipt is not exactly equivalent")
        return receipt

    def _assert_receipt_matches_current_workspace(self, receipt: Mapping[str, Any]) -> None:
        operation = "update" if receipt["after"].get("state") == "present" else "add"
        current, reasons = self.adapter.target_precondition(str(receipt["destination"]), operation)
        if reasons or current is None or not self.adapter.precondition_matches(receipt["after"], current):
            raise ControlPlaneError(
                "workspace_revision_stale",
                "finalized receipt no longer matches the current workspace target",
            )
        allowed_untracked = (
            (str(receipt["destination"]),)
            if receipt.get("operation") in {"add", "tombstone"}
            else ()
        )
        actual_digest = self.adapter.complete_workspace_digest(
            self.allowed_subtrees,
            allowed_untracked_authority=allowed_untracked,
        )
        if actual_digest != receipt.get("post_workspace_digest"):
            raise ControlPlaneError(
                "workspace_revision_stale",
                "finalized receipt no longer matches the complete workspace post-state",
            )

    def apply_workspace(
        self,
        proposal_id: str,
        approval_id: str,
        *,
        host_capability: object = None,
        failpoint: Optional[str] = None,
    ) -> Mapping[str, Any]:
        with self.adapter.writer_lock():
            receipt_path = self._receipt_path(proposal_id)
            if self.adapter.control_artifact_exists("receipts", receipt_path.name):
                receipt = self._load_workspace_receipt(proposal_id)
                if receipt["approval_id"] != approval_id:
                    raise ControlPlaneError("approval_stale", "proposal is finalized under another approval")
                approval = self._load_approval(approval_id)
                self._assert_approval_authorized(
                    approval, host_capability=host_capability, phase="apply"
                )
                self._assert_receipt_matches_current_workspace(receipt)
                return receipt
            ledger = self._load_candidate(proposal_id)
            approval = self._load_approval(approval_id)
            self._assert_approval_authorized(
                approval, host_capability=host_capability, phase="apply"
            )
            if proposal_id not in approval.get("approved_candidate_ids", []):
                raise ControlPlaneError("approval_stale", "approval does not cover proposal")
            if ledger.get("disposition") != "approved" or approval_id not in ledger.get("approval_ids", []):
                raise ControlPlaneError("approval_stale", "candidate approval is stale")
            matching = [
                snapshot
                for snapshot in approval["snapshots"]
                if snapshot.get("proposal_id") == proposal_id
            ]
            if len(matching) != 1 or matching[0].get("candidate_hash") != ledger.get("candidate_hash"):
                raise ControlPlaneError("approval_stale", "approval snapshot is stale")
            self._verify_current_binding(ledger)

            payload = ledger["identity"]["payload"]
            temporal_reasons = temporal_window_reasons(payload, at=datetime.now(timezone.utc))
            if temporal_reasons:
                code = temporal_reasons[0]
                raise ControlPlaneError(code, code)
            operation = payload["operation"]
            if operation == "no_op":
                after_bytes = b""
                before = ledger["identity"]["target_precondition"]
                after = before
                validation: List[Dict[str, Any]] = []
                post_workspace_digest = self.adapter.complete_workspace_digest(self.allowed_subtrees)
            else:
                draft_write = payload["draft_write"]
                if operation == "tombstone":
                    if draft_write.count(TOMBSTONE_APPROVAL_PLACEHOLDER) != 1:
                        raise ControlPlaneError("tombstone_invalid", "tombstone approval binding is invalid")
                    draft_write = draft_write.replace(
                        TOMBSTONE_APPROVAL_PLACEHOLDER, approval_id
                    )
                after_bytes = draft_write.encode("utf-8")
                before = ledger["identity"]["target_precondition"]
                mode = int(before.get("mode", 0o644))
                with self.adapter.prospective_root(payload["destination"], after_bytes, mode) as prospective:
                    validation = self.adapter.run_validators(prospective, self.validators)
                after = {
                    "state": "present",
                    "sha256": sha256_bytes(after_bytes),
                    "mode": mode,
                    "size": len(after_bytes),
                }
                post_workspace_digest = self.adapter.expected_post_workspace_digest(
                    self.allowed_subtrees,
                    relative=payload["destination"],
                    after_bytes=after_bytes,
                    mode=mode,
                    operation=operation,
                )

            intent_body = {
                "schema_version": 1,
                "proposal_id": proposal_id,
                "candidate_hash": ledger["candidate_hash"],
                "approval_id": approval_id,
                "candidate_set_digest": approval["candidate_set_digest"],
                "repository": ledger["identity"]["repository"],
                "source_bindings": ledger["identity"]["source_bindings"],
                "destination": payload["destination"],
                "operation": operation,
                "before": before,
                "after": after,
                "validation": validation,
                "post_workspace_digest": post_workspace_digest,
                "created_at": utc_now(),
            }
            intent = _seal(intent_body)
            intent_path = self._intent_path(proposal_id)
            self.adapter.write_control_artifact(
                "intents",
                intent_path.name,
                "workspace-application-intent",
                intent,
            )
            self._append_candidate_event(
                ledger,
                "application_intent",
                {
                    "approval_id": approval_id,
                    "after_sha256": after.get("sha256"),
                    "validation_digest": digest_object(validation),
                },
            )
            if failpoint == "after_intent":
                raise ControlPlaneError("failpoint", "failpoint after_intent")
            if failpoint == "crash_after_intent":
                os._exit(90)
            if operation != "no_op":
                self._verify_current_binding(self._load_candidate(proposal_id))
                actual_after = self.adapter.atomic_apply(
                    payload["destination"],
                    after_bytes,
                    before,
                    failpoint=failpoint,
                )
                if actual_after != after:
                    raise ControlPlaneError("receipt_invalid", "workspace after state differs from intent")
            allowed_untracked = (
                (str(payload["destination"]),)
                if operation in {"add", "tombstone"}
                else ()
            )
            actual_post_digest = self.adapter.complete_workspace_digest(
                self.allowed_subtrees,
                allowed_untracked_authority=allowed_untracked,
            )
            if actual_post_digest != intent["post_workspace_digest"]:
                raise ControlPlaneError(
                    "workspace_revision_stale",
                    "workspace post-state differs from the validated intent",
                )
            if failpoint == "crash_after_workspace_write":
                os._exit(91)
            if failpoint == "after_workspace_write":
                raise ControlPlaneError("failpoint", "failpoint after_workspace_write")
            return self._write_workspace_receipt(ledger, approval, intent, recovered=False)

    def inspect(self, proposal_id: str) -> Mapping[str, Any]:
        ledger = self._load_candidate(proposal_id)
        result: Dict[str, Any] = {
            "proposal": self._proposal_receipt(ledger),
            "assessment": ledger.get("assessment"),
            "approval_ids": list(ledger.get("approval_ids", [])),
            "event_count": len(ledger["events"]),
            "workspace_receipt": None,
        }
        receipt_path = self._receipt_path(proposal_id)
        if self.adapter.control_artifact_exists("receipts", receipt_path.name):
            result["workspace_receipt"] = self._load_workspace_receipt(proposal_id)
        return result

    def applied_runtime_purge_binding(
        self, proposal_id: str, receipt_id: str
    ) -> Mapping[str, Any]:
        """Reopen one applied tombstone and expose only its sealed purge binding."""

        receipt = self._load_workspace_receipt(proposal_id)
        if (
            receipt.get("receipt_id") != receipt_id
            or receipt.get("operation") != "tombstone"
            or receipt.get("status") != "workspace_applied"
        ):
            raise ControlPlaneError(
                "receipt_invalid", "runtime purge requires the exact applied tombstone receipt"
            )
        self._assert_receipt_matches_current_workspace(receipt)
        ledger = self._load_candidate(proposal_id)
        if ledger["identity"]["payload"].get("operation") != "tombstone":
            raise ControlPlaneError("receipt_invalid", "runtime purge binding is not a tombstone")
        try:
            tombstone = json.loads(str(ledger["identity"]["payload"]["draft_write"]))
            runtime_purge_binding = tombstone["runtime_purge_binding"]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ControlPlaneError(
                "receipt_invalid", "runtime purge selector binding is unavailable"
            ) from error
        return {
            "schema_version": 2,
            "proposal_id": proposal_id,
            "workspace_receipt_id": receipt_id,
            "approval_id": receipt["approval_id"],
            "operation": "tombstone",
            "owner": ledger["identity"]["payload"].get("owner"),
            "source_bindings": ledger["identity"]["source_bindings"],
            "destination": receipt["destination"],
            "authority_after_sha256": receipt["after"]["sha256"],
            "runtime_purge_binding": runtime_purge_binding,
        }

    def audit(self) -> Mapping[str, Any]:
        issues: List[Dict[str, str]] = []
        counts = {"candidates": 0, "approvals": 0, "intents": 0, "receipts": 0}

        for name in self.adapter.list_control_artifacts("candidates", "cand_"):
            path = self.candidates_root / name
            counts["candidates"] += 1
            try:
                ledger = self._load_candidate(path.stem)
                for approval_id in ledger.get("approval_ids", []):
                    approval = self._load_approval(str(approval_id))
                    if path.stem not in approval.get("approved_candidate_ids", []):
                        raise ControlPlaneError(
                            "approval_link_invalid",
                            "candidate links an approval that does not cover it",
                        )
            except ControlPlaneError as error:
                issues.append({"artifact": path.name, "code": error.code})
        for name in self.adapter.list_control_artifacts("approvals", "appr_"):
            path = self.approvals_root / name
            counts["approvals"] += 1
            try:
                approval = self._load_approval(path.stem)
                for proposal_id in approval.get("approved_candidate_ids", []):
                    ledger = self._load_candidate(str(proposal_id))
                    if (
                        path.stem not in ledger.get("approval_ids", [])
                        or ledger.get("disposition") != "approved"
                    ):
                        raise ControlPlaneError(
                            "approval_link_missing",
                            "approval is not reconciled into its candidate ledger",
                        )
            except ControlPlaneError as error:
                issues.append({"artifact": path.name, "code": error.code})
        for name in self.adapter.list_control_artifacts("intents", "cand_"):
            path = self.intents_root / name
            counts["intents"] += 1
            try:
                intent = self._load_intent(path.stem)
                self._load_candidate(path.stem)
                self._load_approval(str(intent.get("approval_id")))
            except ControlPlaneError as error:
                issues.append({"artifact": path.name, "code": error.code})
        for name in self.adapter.list_control_artifacts("receipts", "cand_"):
            path = self.receipts_root / name
            counts["receipts"] += 1
            try:
                self._load_workspace_receipt(path.stem)
            except ControlPlaneError as error:
                issues.append({"artifact": path.name, "code": error.code})
        return {
            "schema_version": 1,
            "ok": not issues,
            "counts": counts,
            "issues": issues,
            "publication_boundary": "workspace_only",
        }

    def recover(self, *, host_capability: object = None) -> Mapping[str, Any]:
        report: Dict[str, Any] = {
            "recovered": [],
            "still_blocked": [],
            "corrupt": [],
            "reason_codes": [],
            "runtime_purge_obligations": [],
        }
        with self.adapter.writer_lock():
            for name in self.adapter.list_control_artifacts("intents", "cand_"):
                proposal_id = Path(name).stem
                try:
                    intent = self._load_intent(proposal_id)
                    ledger = self._load_candidate(proposal_id)
                    approval = self._load_approval(str(intent["approval_id"]))
                    self._assert_approval_authorized(
                        approval,
                        host_capability=host_capability,
                        phase="recover",
                    )
                    if proposal_id not in approval["approved_candidate_ids"]:
                        raise ControlPlaneError("receipt_invalid", "intent approval no longer covers proposal")
                    if (
                        ledger.get("disposition") != "approved"
                        or intent["approval_id"] not in ledger.get("approval_ids", [])
                    ):
                        raise ControlPlaneError("approval_stale", "recovery approval is stale")
                    if intent["candidate_hash"] != ledger["candidate_hash"]:
                        raise ControlPlaneError("receipt_invalid", "intent candidate hash is stale")
                    if not all(result.get("passed") for result in intent.get("validation", [])):
                        raise ControlPlaneError("receipt_invalid", "intent validation evidence is invalid")
                    if self._receipt_path(proposal_id).exists():
                        self._load_workspace_receipt(proposal_id)
                        current = self._load_candidate(proposal_id)
                        receipt = self._load_workspace_receipt(proposal_id)
                        if not any(
                            event.get("kind") == "workspace_applied"
                            and event.get("data", {}).get("receipt_id") == receipt["receipt_id"]
                            for event in current["events"]
                        ):
                            self._append_candidate_event(
                                current,
                                "workspace_applied",
                                {
                                    "receipt_id": receipt["receipt_id"],
                                    "after_sha256": receipt["after"].get("sha256"),
                                    "recovered": True,
                                    "git_published": False,
                                },
                            )
                        if (
                            receipt.get("operation") == "tombstone"
                            and ledger["identity"]["payload"].get("owner")
                            == "agent-memory-deletion-candidate"
                        ):
                            report["runtime_purge_obligations"].append(
                                self.applied_runtime_purge_binding(
                                    proposal_id, str(receipt["receipt_id"])
                                )
                            )
                        continue
                    payload = ledger["identity"]["payload"]
                    current, reasons = self.adapter.target_precondition(
                        payload["destination"],
                        "update" if intent["after"].get("state") == "present" else "add",
                    )
                    if reasons or current is None:
                        raise ControlPlaneError("recovery_required", "cannot inspect recovery target")
                    if self.adapter.precondition_matches(intent["after"], current):
                        temporal_reasons = temporal_window_reasons(
                            payload,
                            at=datetime.now(timezone.utc),
                        )
                        if temporal_reasons:
                            raise ControlPlaneError(temporal_reasons[0], temporal_reasons[0])
                        self._verify_repository_and_sources(ledger)
                        allowed_untracked = (
                            (str(payload["destination"]),)
                            if payload.get("operation") in {"add", "tombstone"}
                            else ()
                        )
                        actual_post_digest = self.adapter.complete_workspace_digest(
                            self.allowed_subtrees,
                            allowed_untracked_authority=allowed_untracked,
                        )
                        if actual_post_digest != intent.get("post_workspace_digest"):
                            raise ControlPlaneError(
                                "workspace_revision_stale",
                                "recovery post-state differs from the validated intent",
                            )
                        receipt = self._write_workspace_receipt(
                            ledger, approval, intent, recovered=True
                        )
                        report["recovered"].append(proposal_id)
                        if (
                            receipt.get("operation") == "tombstone"
                            and payload.get("owner") == "agent-memory-deletion-candidate"
                        ):
                            report["runtime_purge_obligations"].append(
                                self.applied_runtime_purge_binding(
                                    proposal_id, str(receipt["receipt_id"])
                                )
                            )
                    elif self.adapter.precondition_matches(intent["before"], current):
                        report["still_blocked"].append(proposal_id)
                    else:
                        raise ControlPlaneError("recovery_required", "target has an unexpected third digest")
                except ControlPlaneError as error:
                    report["corrupt"].append(proposal_id)
                    report["reason_codes"].append(error.code)
        report["reason_codes"] = sorted(set(report["reason_codes"]))
        report["runtime_purge_obligations"].sort(
            key=lambda binding: str(binding["proposal_id"])
        )
        return report
