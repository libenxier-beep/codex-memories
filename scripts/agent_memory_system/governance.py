"""Compile private evidence candidates into the existing governed proposal plane."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import hashlib
import re
from typing import Any, Mapping, Protocol

from .candidates import _assistant_tool_support
from .store import AgentMemoryStore, utc_now
from memory_control_plane.projection import MemoryProjection, frontmatter


class ProposalPlane(Protocol):
    def prepare(self, payload: Mapping[str, Any], gates: Mapping[str, Any]) -> Mapping[str, Any]:
        ...


class CandidateGovernanceBridge:
    """Proposal-only bridge: it intentionally exposes no authorize/apply method."""

    def __init__(self, store: AgentMemoryStore) -> None:
        self.store = store

    def prepare(
        self,
        plane: ProposalPlane,
        *,
        candidate_id: str,
        destination: str,
        scope: str,
        applies_to: str,
        gates: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        candidate = next(
            (row for row in self.store.list_candidates() if row["candidate_id"] == candidate_id),
            None,
        )
        if candidate is None:
            raise ValueError("candidate is unavailable")
        if candidate["status"] != "proposed" or not candidate["requires_authorization"]:
            raise ValueError("candidate is not eligible for governed proposal")
        evidence = next(
            (
                row
                for row in self.store.list_evidence(candidate["session_id"])
                if row["event_id"] == candidate["source_event_id"]
            ),
            None,
        )
        if evidence is None or evidence["content_hash"] != candidate["source_text_hash"]:
            raise ValueError("candidate provenance cannot be reopened")
        if candidate["source_span"] != evidence["content"][candidate["span_start"] : candidate["span_end"]]:
            raise ValueError("candidate source span no longer matches evidence")
        supporting_evidence: list[Mapping[str, Any]] = []
        if evidence.get("evidence_type") == "assistant":
            supporting_evidence = _assistant_tool_support(
                self.store.list_evidence(candidate["session_id"]), evidence
            )
            if not supporting_evidence:
                raise ValueError("assistant candidate has no complete supporting tool pair")
        self._validate_destination(candidate, destination, scope, applies_to)
        repository = getattr(plane, "repository", None)
        target = repository / PurePosixPath(destination) if repository is not None else None
        operation = "update" if target is not None and target.is_file() else "add"
        if operation == "update":
            self._validate_update_target(candidate, target)
        draft = self._draft(candidate, destination, scope, applies_to)
        payload = {
            "schema_version": 1,
            "normalization_version": 1,
            "operation": operation,
            "destination": destination,
            "draft_write": draft,
            "scope": scope,
            "applies_to": applies_to,
            "owner": "agent-memory-candidate",
            "source_refs": [
                {
                    "kind": "conversation_turn",
                    "ref": "{}#L{}:{}-{}".format(
                        candidate["source_path"], candidate["source_line"],
                        candidate["span_start"], candidate["span_end"],
                    ),
                    "sha256": candidate["source_text_hash"],
                },
                *[
                    {
                        "kind": str(row["evidence_type"]),
                        "ref": "{}#L{}".format(row["source_path"], row["source_line"]),
                        "sha256": str(row["content_hash"]),
                    }
                    for row in supporting_evidence
                ],
            ],
            "source_revision": "agent-memory-evidence:{}".format(candidate["source_event_id"]),
            # Evidence occurrence time is provenance, not an activation time.
            # Approval/application determines activation, so a clock-skewed or
            # imported transcript must not create a future-dated executable
            # proposal.
            "valid_from": None,
            "valid_to": candidate["expires_at"],
            "sensitivity": self._sensitivity(candidate, evidence),
        }
        return plane.prepare(payload, gates)


    def _validate_update_target(
        self, candidate: Mapping[str, Any], target: Path
    ) -> None:
        if target.is_symlink():
            raise ValueError("existing destination is not linked to the candidate lineage")
        try:
            metadata = frontmatter(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise ValueError(
                "existing destination is not linked to the candidate lineage"
            ) from None
        related_targets = {
            str(row["target_candidate_id"])
            for row in self.store.list_relations()
            if row.get("source_candidate_id") == candidate.get("candidate_id")
            and row.get("relation_type") in {"update", "supersede", "conflict"}
        }
        lineage = {str(candidate.get("candidate_id", ""))} | related_targets
        if metadata.get("source_candidate") not in lineage:
            raise ValueError("existing destination is not linked to the candidate lineage")

    def prepare_tombstone(
        self,
        plane: ProposalPlane,
        *,
        candidate_id: str,
        gates: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Prepare one canonical tombstone; authorization and apply stay external."""
        deletion, evidence = self._reopen_candidate(candidate_id)
        if deletion.get("memory_class") != "deletion_request":
            raise ValueError("candidate is not a deletion request")
        targets = {
            str(row["target_candidate_id"])
            for row in self.store.list_relations()
            if row.get("relation_type") == "delete"
            and row.get("source_candidate_id") == candidate_id
        }
        if not targets:
            raise ValueError("deletion request has no source-bound target")
        repository = getattr(plane, "repository", None)
        adapter = getattr(plane, "adapter", None)
        if not isinstance(repository, Path) or adapter is None:
            raise ValueError("proposal plane cannot reopen canonical authority")
        revision = str(adapter.base_revision())
        projection = MemoryProjection(
            repository=repository,
            index_path=repository / "control_plane" / ".tombstone-lookup.sqlite",
            authority_roots=("core", "platform", "learnings"),
            force_no_fts=True,
        )
        items, _ = projection._committed_state(revision)
        matches = []
        for item in items:
            metadata = frontmatter(str(item.get("content", "")))
            if metadata.get("source_candidate") in targets and not item.get("tombstoned"):
                matches.append(item)
        if len(matches) != 1:
            raise ValueError("deletion target does not resolve to one active canonical item")
        target = matches[0]
        item_id = str(target["item_id"])
        authority_path = str(target["authority_path"])
        authority_sha = str(target["authority_sha256"])
        candidates = self.store.list_candidates()
        target_candidates = {
            str(candidate["candidate_id"]): candidate
            for candidate in candidates
            if str(candidate.get("candidate_id") or "") in targets
        }
        if set(target_candidates) != targets:
            raise ValueError("deletion target candidates cannot be reopened exactly")
        sessions = {
            str(candidate.get("session_id") or "")
            for candidate in target_candidates.values()
        }
        sessions.add(str(deletion.get("session_id") or ""))
        if "" in sessions:
            raise ValueError("deletion target sessions are invalid")
        runtime_purge_binding = {
            "schema_version": 1,
            "scope": "whole_sessions",
            "target_candidate_ids": sorted(targets),
            "session_selector_digests": sorted(
                hashlib.sha256(session.encode("utf-8")).hexdigest()
                for session in sessions
            ),
        }
        tombstone_id = "tomb_{}".format(candidate_id.removeprefix("cand_")[:32])
        destination = "lifecycle/tombstones/{}.json".format(tombstone_id)
        body = {
            "schema_version": 1,
            "tombstone_id": tombstone_id,
            "item_id": item_id,
            "authority_path": authority_path,
            "authority_sha256": authority_sha,
            "reason": str(deletion["claim"]),
            # The control plane replaces this exact token after the approval
            # ID exists.  The transformation is part of tombstone operation
            # semantics and the final bytes are sealed in intent + receipt.
            "approval_receipt": "__MEMORY_CONTROL_APPROVAL_RECEIPT__",
            "runtime_purge_binding": runtime_purge_binding,
            # Transcript occurrence is provenance and may be imported or
            # clock-skewed.  The overlay activation artifact binds preparation
            # time instead of inheriting a future evidence timestamp.
            "created_at": utc_now(),
        }
        metadata = frontmatter(str(target["content"]))
        payload = {
            "schema_version": 1,
            "normalization_version": 1,
            "operation": "tombstone",
            "destination": destination,
            "draft_write": json.dumps(body, ensure_ascii=False, sort_keys=True) + "\n",
            "scope": str(metadata.get("scope") or target.get("scope") or "global"),
            "applies_to": str(metadata.get("applies_to") or target.get("applies_to") or "all"),
            "owner": "agent-memory-deletion-candidate",
            "source_refs": [
                {
                    "kind": "conversation_turn",
                    "ref": "{}#L{}:{}-{}".format(
                        deletion["source_path"], deletion["source_line"],
                        deletion["span_start"], deletion["span_end"],
                    ),
                    "sha256": deletion["source_text_hash"],
                },
                {
                    "kind": "repository_file",
                    "ref": authority_path,
                    "sha256": authority_sha,
                },
            ],
            "source_revision": revision,
            "valid_from": None,
            "valid_to": None,
            "sensitivity": "work",
        }
        return plane.prepare(payload, gates)

    def _reopen_candidate(
        self, candidate_id: str
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        candidate = next(
            (row for row in self.store.list_candidates() if row["candidate_id"] == candidate_id),
            None,
        )
        if candidate is None or candidate["status"] != "proposed" or not candidate["requires_authorization"]:
            raise ValueError("candidate is unavailable or not proposal eligible")
        evidence = next(
            (
                row
                for row in self.store.list_evidence(candidate["session_id"])
                if row["event_id"] == candidate["source_event_id"]
            ),
            None,
        )
        if evidence is None or evidence["content_hash"] != candidate["source_text_hash"]:
            raise ValueError("candidate provenance cannot be reopened")
        if candidate["source_span"] != evidence["content"][candidate["span_start"] : candidate["span_end"]]:
            raise ValueError("candidate source span no longer matches evidence")
        return candidate, evidence

    @staticmethod
    def _validate_destination(
        candidate: Mapping[str, Any], destination: str, scope: str, applies_to: str
    ) -> None:
        path = PurePosixPath(destination)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("destination is not allowed for candidate class")
        if path.suffix.lower() != ".md" or applies_to not in {"codex", "all"}:
            raise ValueError("destination is not allowed for candidate class")
        memory_class = str(candidate.get("memory_class", ""))
        root = path.parts[0] if path.parts else ""
        allowed = {
            "fact": {("learnings", "learning")},
            "preference": {("learnings", "learning")},
            "method": {("learnings", "learning")},
            "lesson": {("learnings", "learning")},
            "principle": {
                ("core", "global"),
                ("platform", "platform"),
                ("learnings", "learning"),
            },
        }
        if (root, scope) not in allowed.get(memory_class, set()):
            raise ValueError("destination is not allowed for candidate class")
        if destination in {
            "core/load_policy.md",
            "core/global_principles.md",
            "core/collaboration_defaults.md",
        }:
            raise ValueError("destination is not allowed for candidate class")

    @staticmethod
    def _sensitivity(
        candidate: Mapping[str, Any], evidence: Mapping[str, Any]
    ) -> str:
        text = "{} {}".format(candidate.get("claim", ""), evidence.get("content", ""))
        folded = text.casefold()
        if re.search(
            r"(?:密码|口令|密钥|token|api[_ -]?key|银行卡|身份证|护照|credential|secret)",
            folded,
        ):
            return "credential"
        personal_domains = (
            "姓名", "生日", "年龄", "住在", "住址", "常驻", "城市", "电话", "手机号",
            "邮箱", "病历", "疾病", "诊断", "健康", "药物", "收入", "工资", "家庭", "伴侣",
            "个人画像", "用户画像", "私人档案", "private profile",
        )
        inherently_profile = (
            "个人画像", "用户画像", "私人档案", "private profile", "个人身份",
        )
        first_person = any(token in folded for token in ("我", "本人", "我的", "i ", "my "))
        if any(token in folded for token in inherently_profile) or (
            first_person and any(token in folded for token in personal_domains)
        ):
            return "private"
        if "公开" in folded or "public" in folded:
            return "public"
        return "work"

    @staticmethod
    def _draft(
        candidate: Mapping[str, Any], destination: str, scope: str, applies_to: str
    ) -> str:
        item_id = "memory_" + str(candidate["candidate_id"])[5:29]
        return (
            "---\n"
            "id: {item_id}\n"
            "scope: {scope}\n"
            "applies_to: {applies_to}\n"
            "status: active\n"
            "authorization_state: user_approved\n"
            "provenance_trust: source_bound_candidate\n"
            "privacy_class: private_local\n"
            "trust_class: source_bound_candidate\n"
            "valid_from: {valid_from}\n"
            "valid_to: {valid_to}\n"
            "source_candidate: {candidate_id}\n"
            "source_event: {source_event}\n"
            "---\n\n"
            "# Governed memory candidate\n\n"
            "{claim}\n"
        ).format(
            item_id=item_id,
            scope=scope,
            applies_to=applies_to,
            valid_from="",
            valid_to=candidate["expires_at"] or "",
            candidate_id=candidate["candidate_id"],
            source_event=candidate["source_event_id"],
            claim=candidate["claim"],
        )


class RuntimeDeletionCoordinator:
    """Propagate one sealed canonical tombstone receipt into private runtime copies."""

    _SOURCE_REF = re.compile(
        r"^(?P<path>.+)#L(?P<line>[1-9][0-9]*):(?P<start>[0-9]+)-(?P<end>[0-9]+)$"
    )

    def __init__(
        self,
        store: AgentMemoryStore,
        *,
        index_paths: tuple[Path, ...] = (),
    ) -> None:
        self.store = store
        self.index_paths = tuple(path.resolve(strict=False) for path in index_paths)

    def purge_applied_tombstone(
        self,
        binding: Mapping[str, Any],
        *,
        now: str,
    ) -> Mapping[str, Any]:
        if (
            set(binding) != {
                "schema_version", "proposal_id", "workspace_receipt_id",
                "approval_id", "operation", "owner", "source_bindings", "destination",
                "authority_after_sha256", "runtime_purge_binding",
            }
            or binding.get("schema_version") != 2
            or binding.get("operation") != "tombstone"
            or binding.get("owner") != "agent-memory-deletion-candidate"
        ):
            raise ValueError("runtime purge binding is invalid")
        sealed_purge = binding.get("runtime_purge_binding")
        if (
            not isinstance(sealed_purge, Mapping)
            or set(sealed_purge) != {
                "schema_version", "scope", "target_candidate_ids",
                "session_selector_digests",
            }
            or sealed_purge.get("schema_version") != 1
            or sealed_purge.get("scope") != "whole_sessions"
        ):
            raise ValueError("runtime purge selector binding is invalid")
        sealed_targets = sealed_purge.get("target_candidate_ids")
        sealed_sessions = sealed_purge.get("session_selector_digests")
        if (
            not isinstance(sealed_targets, list)
            or not sealed_targets
            or sealed_targets != sorted(set(sealed_targets))
            or any(re.fullmatch(r"cand_[0-9a-f]{64}", str(item)) is None for item in sealed_targets)
            or not isinstance(sealed_sessions, list)
            or not sealed_sessions
            or sealed_sessions != sorted(set(sealed_sessions))
            or any(re.fullmatch(r"[0-9a-f]{64}", str(item)) is None for item in sealed_sessions)
        ):
            raise ValueError("runtime purge selector binding is invalid")
        source_bindings = binding.get("source_bindings")
        if not isinstance(source_bindings, list):
            raise ValueError("runtime purge source bindings are invalid")
        workspace_receipt_id = str(binding["workspace_receipt_id"])
        existing_receipt = self.store.get_authority_purge_receipt(
            workspace_receipt_id
        )
        if existing_receipt is not None:
            if existing_receipt.get("session_selector_digests") != sealed_sessions:
                raise ValueError("runtime purge receipt does not match sealed sessions")
            return self._runtime_receipt(
                workspace_receipt_id,
                existing_receipt,
            )
        conversation = [
            item for item in source_bindings
            if isinstance(item, Mapping) and item.get("kind") == "conversation_turn"
        ]
        if len(conversation) != 1:
            raise ValueError("runtime purge requires one conversation source")
        source = conversation[0]
        matched = self._SOURCE_REF.fullmatch(str(source.get("ref") or ""))
        if matched is None or not re.fullmatch(
            r"[0-9a-f]{64}", str(source.get("sha256") or "")
        ):
            raise ValueError("runtime purge conversation source is invalid")
        deletion_candidates = [
            candidate
            for candidate in self.store.list_candidates()
            if candidate.get("memory_class") == "deletion_request"
            and candidate.get("status") == "proposed"
            and candidate.get("source_path") == matched.group("path")
            and int(candidate.get("source_line") or 0) == int(matched.group("line"))
            and int(
                candidate.get("span_start")
                if candidate.get("span_start") is not None
                else -1
            ) == int(matched.group("start"))
            and int(
                candidate.get("span_end")
                if candidate.get("span_end") is not None
                else -1
            ) == int(matched.group("end"))
            and candidate.get("source_text_hash") == source.get("sha256")
        ]
        if len(deletion_candidates) != 1:
            raise ValueError("runtime deletion candidate cannot be reopened exactly")
        deletion = deletion_candidates[0]
        target_ids = {
            str(relation["target_candidate_id"])
            for relation in self.store.list_relations()
            if relation.get("source_candidate_id") == deletion["candidate_id"]
            and relation.get("relation_type") == "delete"
        }
        if not target_ids:
            raise ValueError("runtime deletion has no source-bound target")
        if sorted(target_ids) != sealed_targets:
            raise ValueError("runtime deletion does not match sealed targets")
        candidates = self.store.list_candidates()
        sessions = {
            str(candidate["session_id"])
            for candidate in candidates
            if candidate["candidate_id"] in target_ids
        }
        sessions.add(str(deletion["session_id"]))
        if "" in sessions:
            raise ValueError("runtime deletion sessions are invalid")
        session_digests = sorted(
            hashlib.sha256(session.encode("utf-8")).hexdigest()
            for session in sessions
        )
        if session_digests != sealed_sessions:
            raise ValueError("runtime deletion does not match sealed sessions")
        purge_receipt = self.store.purge_authority_sessions(
            tuple(sorted(sessions)),
            authority_receipt_id=workspace_receipt_id,
            now=now,
        )
        return self._runtime_receipt(workspace_receipt_id, purge_receipt)

    def _runtime_receipt(
        self,
        workspace_receipt_id: str,
        purge_receipt: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        invalidated = []
        for path in self.index_paths:
            digest = hashlib.sha256(str(path).encode("utf-8")).hexdigest()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            invalidated.append(digest)
        return {
            "schema_version": 1,
            "status": "runtime_purged",
            "workspace_receipt_id": workspace_receipt_id,
            "session_selector_digests": list(
                purge_receipt["session_selector_digests"]
            ),
            "purge_receipt_ids": [str(purge_receipt["receipt_id"])],
            "invalidated_index_path_digests": sorted(invalidated),
        }
