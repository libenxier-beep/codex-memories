from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent_memory_system.candidates import CandidateFormer  # noqa: E402
from agent_memory_system.capture import TranscriptCapture  # noqa: E402
from agent_memory_system.governance import (  # noqa: E402
    CandidateGovernanceBridge,
    RuntimeDeletionCoordinator,
)
from agent_memory_system.store import AgentMemoryStore  # noqa: E402
from memory_control_plane import MemoryControlPlane, ValidatorSpec  # noqa: E402
from memory_control_plane.projection import MemoryProjection  # noqa: E402
from memory_control_plane.recall_policy import RecallPolicy  # noqa: E402
from memory_control import control_plane  # noqa: E402


def approved_private_policy() -> RecallPolicy:
    return RecallPolicy.from_mapping(
        {
            "schema_version": 1,
            "scopes": ["learning"],
            "applies_to": "codex",
            "as_of": "2026-08-19T00:00:00Z",
            "allowed_authorization_states": ["user_approved"],
            "allowed_provenance_trust": ["source_bound_candidate"],
            "allowed_privacy_classes": ["private_local"],
            "high_stakes": False,
            "private_profile": True,
            "eligible_lifecycles": ["active", "legacy"],
            "require_source_revision_match": True,
            "require_content_hash_match": True,
            "require_canonical_relevance": True,
            "exclude_tombstoned": True,
            "exclude_deleted": True,
        }
    )


class AgentMemoryGovernanceBridgeTests(unittest.TestCase):
    def test_authorized_candidate_draft_separates_authorization_from_provenance(self) -> None:
        draft = CandidateGovernanceBridge._draft(
            {
                "candidate_id": "cand_1234567890abcdef1234567890abcdef",
                "source_event_id": "event-1",
                "expires_at": None,
                "claim": "Use a reviewed deterministic rule.",
            },
            "learnings/reviewed.md",
            "learning",
            "codex",
        )

        self.assertIn("authorization_state: user_approved\n", draft)
        self.assertIn("provenance_trust: source_bound_candidate\n", draft)
        self.assertIn("privacy_class: private_local\n", draft)

    def git(self, root: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=root, check=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout.strip()

    def test_product_control_plane_admits_only_governed_lifecycle_tombstones(self) -> None:
        self.assertIn("lifecycle", control_plane(ROOT).allowed_subtrees)

    def test_real_candidate_stays_quarantined_until_existing_authorize_and_receipt_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.name", "Governance Fixture")
            self.git(root, "config", "user.email", "governance@example.invalid")
            (root / "core").mkdir()
            (root / "core" / "base.md").write_text(
                "---\nid: base\nscope: global\nstatus: active\n---\n\n# Base\n",
                encoding="utf-8",
            )
            (root / "validate.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "baseline")

            transcript = root / "transcript.jsonl"
            transcript.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-14T08:00:00Z",
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "user",
                            "content": [
                                {"type": "input_text", "text": "事实：仓库默认测试命令是 python3 -m unittest"}
                            ],
                        },
                    },
                    ensure_ascii=False,
                ) + "\n",
                encoding="utf-8",
            )
            store = AgentMemoryStore(root / ".runtime" / "agent-memory.sqlite")
            TranscriptCapture(store).capture_jsonl("s1", transcript)
            CandidateFormer(store).form_candidates("s1")
            candidate = store.list_candidates("s1")[0]

            host_capability = object()

            def verify_host_capability(candidate_capability, request):
                if candidate_capability is host_capability and request.get("phase") in {
                    "authorize",
                    "apply",
                    "recover",
                }:
                    return "cap_" + "c" * 64
                return None

            plane = MemoryControlPlane(
                repository=root,
                control_root=root / "control_plane",
                repository_id="governance-fixture",
                policy_version="test-v1",
                allowed_subtrees=("core", "platform", "learnings", "lifecycle"),
                validators=(ValidatorSpec(name="fixture", argv=(sys.executable, "validate.py"), timeout_seconds=5),),
                host_authorization_verifier=verify_host_capability,
            )
            bridge = CandidateGovernanceBridge(store)
            proposal = bridge.prepare(
                plane,
                candidate_id=candidate["candidate_id"],
                destination="learnings/auto-test-command.md",
                scope="learning",
                applies_to="codex",
                gates={
                    "prompt_injection": "pass",
                    "executable_payload": "pass",
                    "provenance": "pass",
                    "scope": "pass",
                    "stability": "pass",
                    "high_stakes": "pass",
                    "authority_conflict": "pass",
                },
            )

            self.assertEqual(proposal["disposition"], "quarantined")
            self.assertFalse((root / "learnings" / "auto-test-command.md").exists())
            plane.assess(
                proposal["proposal_id"],
                {
                    "scores": {
                        "recurrence": 2,
                        "transferability": 2,
                        "stability": 2,
                        "impact": 2,
                        "contamination_risk": 2,
                    },
                    "deduplication": "novel",
                    "conflict": "none",
                },
            )
            approval = plane.authorize(
                proposal["candidate_set_digest"],
                {
                    "mode": "approve_ids",
                    "candidate_ids": [proposal["proposal_id"]],
                    "actor_claim": "user",
                    "current_turn_ref": "turn:explicit-approval",
                },
                host_capability=host_capability,
            )
            receipt = plane.apply_workspace(
                proposal["proposal_id"],
                approval["approval_id"],
                host_capability=host_capability,
            )

            self.assertEqual(receipt["status"], "workspace_applied")
            applied = root / "learnings" / "auto-test-command.md"
            self.assertTrue(applied.is_file())
            self.assertIn(candidate["candidate_id"], applied.read_text(encoding="utf-8"))
            self.git(root, "add", "learnings/auto-test-command.md")
            self.git(root, "commit", "-m", "publish approved candidate")

            update_transcript = root / "update.jsonl"
            update_transcript.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-14T08:30:00Z",
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "user",
                            "content": [{"type": "input_text", "text": "事实：仓库默认测试命令是 python3 -m unittest discover"}],
                        },
                    },
                    ensure_ascii=False,
                ) + "\n",
                encoding="utf-8",
            )
            TranscriptCapture(store).capture_jsonl("s1", update_transcript)
            CandidateFormer(store).form_candidates("s1")
            updated_candidate = next(
                row
                for row in store.list_candidates("s1")
                if "unittest discover" in row["claim"]
            )
            updated_proposal = bridge.prepare(
                plane,
                candidate_id=updated_candidate["candidate_id"],
                destination="learnings/auto-test-command.md",
                scope="learning",
                applies_to="codex",
                gates=self.gates(),
            )
            plane.assess(
                updated_proposal["proposal_id"],
                {
                    "scores": {key: 2 for key in ("recurrence", "transferability", "stability", "impact", "contamination_risk")},
                    "deduplication": "novel",
                    "conflict": "none",
                },
            )
            updated_approval = plane.authorize(
                updated_proposal["candidate_set_digest"],
                {
                    "mode": "approve_ids",
                    "candidate_ids": [updated_proposal["proposal_id"]],
                    "actor_claim": "user",
                    "current_turn_ref": "turn:explicit-update-approval",
                },
                host_capability=host_capability,
            )
            updated_receipt = plane.apply_workspace(
                updated_proposal["proposal_id"],
                updated_approval["approval_id"],
                host_capability=host_capability,
            )
            self.assertEqual("update", updated_receipt["operation"])
            self.assertIn("unittest discover", applied.read_text(encoding="utf-8"))
            self.git(root, "add", "learnings/auto-test-command.md")
            self.git(root, "commit", "-m", "publish authorized update")

            projection = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            projection.build(context=approved_private_policy())
            recalled = projection.recall(
                "unittest",
                context=approved_private_policy(),
            )
            self.assertEqual(recalled["status"], "hit")
            self.assertTrue(recalled["matches"][0]["canonical_reopened"])

            deletion_transcript = root / "delete.jsonl"
            deletion_transcript.write_text(
                json.dumps(
                    {
                        "timestamp": "2099-08-14T09:00:00Z",
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "user",
                            "content": [{"type": "input_text", "text": "请忘记仓库默认测试命令"}],
                        },
                    },
                    ensure_ascii=False,
                ) + "\n",
                encoding="utf-8",
            )
            # A user can publish and later delete a memory in one long-running
            # Codex session. Runtime deletion must not require two session IDs.
            TranscriptCapture(store).capture_jsonl("s1", deletion_transcript)
            CandidateFormer(store).form_candidates("s1")
            deletion = next(
                row
                for row in store.list_candidates("s1")
                if row["memory_class"] == "deletion_request"
            )
            tombstone = bridge.prepare_tombstone(
                plane,
                candidate_id=deletion["candidate_id"],
                gates=self.gates(),
            )
            self.assertEqual("quarantined", tombstone["disposition"])
            plane.assess(
                tombstone["proposal_id"],
                {
                    "scores": {
                        "recurrence": 2,
                        "transferability": 2,
                        "stability": 2,
                        "impact": 2,
                        "contamination_risk": 2,
                    },
                    "deduplication": "novel",
                    "conflict": "none",
                },
            )
            deletion_approval = plane.authorize(
                tombstone["candidate_set_digest"],
                {
                    "mode": "approve_ids",
                    "candidate_ids": [tombstone["proposal_id"]],
                    "actor_claim": "user",
                    "current_turn_ref": "turn:explicit-delete-approval",
                },
                host_capability=host_capability,
            )
            deletion_receipt = plane.apply_workspace(
                tombstone["proposal_id"],
                deletion_approval["approval_id"],
                host_capability=host_capability,
            )
            tombstone_path = root / deletion_receipt["destination"]
            tombstone_body = json.loads(tombstone_path.read_text(encoding="utf-8"))
            self.assertEqual(deletion_approval["approval_id"], tombstone_body["approval_receipt"])
            self.assertFalse(tombstone_body["created_at"].startswith("2099-"))
            self.assertEqual("tombstone", deletion_receipt["operation"])
            self.assertTrue(applied.is_file(), "tombstones suppress recall without physically deleting authority")
            runtime_binding = plane.applied_runtime_purge_binding(
                tombstone["proposal_id"], deletion_receipt["receipt_id"]
            )
            sealed_purge = runtime_binding["runtime_purge_binding"]
            expected_targets = sorted(
                str(row["target_candidate_id"])
                for row in store.list_relations()
                if row.get("relation_type") == "delete"
                and row.get("source_candidate_id") == deletion["candidate_id"]
            )
            self.assertEqual("whole_sessions", sealed_purge["scope"])
            self.assertEqual(expected_targets, sealed_purge["target_candidate_ids"])
            self.assertTrue(sealed_purge["session_selector_digests"])
            mutated_relations = store.list_relations() + [
                {
                    "source_candidate_id": deletion["candidate_id"],
                    "target_candidate_id": "cand_" + "f" * 64,
                    "relation_type": "delete",
                }
            ]
            with mock.patch.object(store, "list_relations", return_value=mutated_relations):
                with self.assertRaisesRegex(ValueError, "sealed target"):
                    RuntimeDeletionCoordinator(store).purge_applied_tombstone(
                        runtime_binding,
                        now=deletion_receipt["completed_at"],
                    )
            try:
                runtime_purge = RuntimeDeletionCoordinator(
                    store,
                    index_paths=(projection.index_path, root / ".runtime" / "hybrid.sqlite"),
                ).purge_applied_tombstone(
                    runtime_binding,
                    now=deletion_receipt["completed_at"],
                )
            except ValueError as error:
                self.fail(f"same-session canonical deletion was rejected: {error}")
            self.assertEqual("runtime_purged", runtime_purge["status"])
            self.assertEqual([], store.list_evidence())
            self.assertEqual([], store.list_candidates())
            self.assertFalse(projection.index_path.exists())
            retry_runtime_purge = RuntimeDeletionCoordinator(
                store,
                index_paths=(projection.index_path, root / ".runtime" / "hybrid.sqlite"),
            ).purge_applied_tombstone(
                plane.applied_runtime_purge_binding(
                    tombstone["proposal_id"], deletion_receipt["receipt_id"]
                ),
                now=deletion_receipt["completed_at"],
            )
            self.assertEqual(runtime_purge, retry_runtime_purge)
            authority_receipts = [
                receipt
                for receipt in store.list_purge_receipts()
                if receipt["reason"] == "authority"
            ]
            self.assertEqual(1, len(authority_receipts))
            self.assertEqual(
                runtime_purge["session_selector_digests"],
                authority_receipts[0]["session_selector_digests"],
            )
            self.git(root, "add", deletion_receipt["destination"])
            self.git(root, "commit", "-m", "publish authorized tombstone")
            projection.build(context=approved_private_policy())
            deleted = projection.recall(
                "unittest",
                context=approved_private_policy(),
            )
            self.assertEqual("no_safe_match", deleted["status"])

    def test_private_profile_is_rejected_before_persistence_and_fact_cannot_enter_ring_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.name", "Governance Fixture")
            self.git(root, "config", "user.email", "governance@example.invalid")
            (root / "core").mkdir()
            (root / "core" / "base.md").write_text("---\nid: base\nscope: global\nstatus: active\n---\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "baseline")
            transcript = root / "transcript.jsonl"
            transcript.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-14T08:00:00Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "事实：用户画像是高风险投资者"}]},
                    },
                    ensure_ascii=False,
                ) + "\n",
                encoding="utf-8",
            )
            store = AgentMemoryStore(root / ".runtime" / "state.sqlite")
            TranscriptCapture(store).capture_jsonl("s1", transcript)
            CandidateFormer(store).form_candidates("s1")
            candidate = store.list_candidates("s1")[0]
            plane = MemoryControlPlane(
                repository=root,
                control_root=root / "control_plane",
                repository_id="governance-fixture",
                policy_version="test-v1",
                allowed_subtrees=("core", "platform", "learnings", "lifecycle"),
                validators=(),
            )
            bridge = CandidateGovernanceBridge(store)
            with self.assertRaisesRegex(ValueError, "destination is not allowed"):
                bridge.prepare(
                    plane,
                    candidate_id=candidate["candidate_id"],
                    destination="core/profile.md",
                    scope="global",
                    applies_to="codex",
                    gates=self.gates(),
                )
            rejected = bridge.prepare(
                plane,
                candidate_id=candidate["candidate_id"],
                destination="learnings/profile.md",
                scope="learning",
                applies_to="codex",
                gates=self.gates(),
            )
            self.assertEqual("rejected", rejected["disposition"])
            self.assertIn("disallowed_personal_data", rejected["reason_codes"])
            self.assertFalse((root / "control_plane" / "candidates").exists())

    def test_candidate_cannot_overwrite_unrelated_existing_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.name", "Governance Fixture")
            self.git(root, "config", "user.email", "governance@example.invalid")
            (root / "learnings").mkdir()
            (root / "learnings" / "unrelated.md").write_text(
                "---\nid: unrelated\nscope: learning\nstatus: active\n---\n\n# Unrelated\n",
                encoding="utf-8",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "baseline")
            transcript = root / "transcript.jsonl"
            transcript.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-14T08:00:00Z",
                        "type": "response_item",
                        "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "事实：仓库默认测试命令是 python3 -m unittest"}]},
                    },
                    ensure_ascii=False,
                ) + "\n",
                encoding="utf-8",
            )
            store = AgentMemoryStore(root / ".runtime" / "state.sqlite")
            TranscriptCapture(store).capture_jsonl("s1", transcript)
            CandidateFormer(store).form_candidates("s1")
            candidate = store.list_candidates("s1")[0]
            plane = MemoryControlPlane(
                repository=root,
                control_root=root / "control_plane",
                repository_id="governance-fixture",
                policy_version="test-v1",
                allowed_subtrees=("core", "platform", "learnings", "lifecycle"),
                validators=(),
            )
            with self.assertRaisesRegex(ValueError, "not linked to the candidate lineage"):
                CandidateGovernanceBridge(store).prepare(
                    plane,
                    candidate_id=candidate["candidate_id"],
                    destination="learnings/unrelated.md",
                    scope="learning",
                    applies_to="codex",
                    gates=self.gates(),
                )

    def test_assistant_lesson_proposal_cites_the_supporting_tool_pair(self) -> None:
        class RecordingPlane:
            repository = None

            def prepare(self, payload, gates):
                return {"payload": payload, "gates": gates}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = AgentMemoryStore(root / "state.sqlite")
            for number in range(1, 19):
                call_id = f"tool-{number:02d}"
                store.capture_hook_observation(
                    session_id="assistant-lesson", event_name="PreToolUse",
                    evidence_type="tool_call", role=None,
                    content='{"name":"exec_command","arguments":{"cmd":"tests"}}',
                    cwd=str(root), source_event_id=call_id,
                    metadata={"call_id": call_id, "turn_id": "turn-1"},
                )
                store.capture_hook_observation(
                    session_id="assistant-lesson", event_name="PostToolUse",
                    evidence_type="tool_result", role=None,
                    content=f"result {number}: old reader failed; new reader passed",
                    cwd=str(root), source_event_id=call_id + "-result",
                    metadata={"call_id": call_id, "turn_id": "turn-1"},
                )
            store.capture_hook_observation(
                session_id="assistant-lesson", event_name="Stop",
                evidence_type="assistant", role="assistant",
                content="这个 bug 最终说明 schema migration 必须同时验证新旧读路径。",
                cwd=str(root), source_event_id="turn-1",
                metadata={"turn_id": "turn-1"},
            )
            CandidateFormer(store).form_candidates("assistant-lesson")
            candidate = store.list_candidates("assistant-lesson")[0]

            proposal = CandidateGovernanceBridge(store).prepare(
                RecordingPlane(), candidate_id=candidate["candidate_id"],
                destination="learnings/schema-migration.md", scope="learning",
                applies_to="codex", gates=self.gates(),
            )

        refs = proposal["payload"]["source_refs"]
        self.assertEqual("conversation_turn", refs[0]["kind"])
        self.assertEqual(17, len(refs), "one assistant span plus eight recent tool pairs")
        self.assertEqual(
            ["tool_call", "tool_result"] * 8,
            [item["kind"] for item in refs[1:]],
        )
        self.assertTrue(any(item["ref"].endswith("#L18") for item in refs))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in refs))

    def test_real_control_plane_accepts_assistant_lesson_tool_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.git(root, "init", "-b", "main")
            self.git(root, "config", "user.name", "Governance Fixture")
            self.git(root, "config", "user.email", "governance@example.invalid")
            (root / "core").mkdir()
            (root / "core" / "base.md").write_text(
                "---\nid: base\nscope: global\nstatus: active\n---\n\n# Base\n",
                encoding="utf-8",
            )
            self.git(root, "add", ".")
            self.git(root, "commit", "-m", "baseline")

            store = AgentMemoryStore(root / ".runtime" / "state.sqlite")
            store.capture_hook_observation(
                session_id="assistant-lesson",
                event_name="PreToolUse",
                evidence_type="tool_call",
                role=None,
                content='{"name":"exec_command","arguments":{"cmd":"tests"}}',
                cwd=str(root),
                source_event_id="tool-1",
                metadata={"call_id": "tool-1", "turn_id": "turn-1"},
            )
            store.capture_hook_observation(
                session_id="assistant-lesson",
                event_name="PostToolUse",
                evidence_type="tool_result",
                role=None,
                content="old reader failed; new reader passed",
                cwd=str(root),
                source_event_id="tool-1-result",
                metadata={"call_id": "tool-1", "turn_id": "turn-1"},
            )
            store.capture_hook_observation(
                session_id="assistant-lesson",
                event_name="Stop",
                evidence_type="assistant",
                role="assistant",
                content="这个 bug 最终说明 schema migration 必须同时验证新旧读路径。",
                cwd=str(root),
                source_event_id="turn-1",
                metadata={"turn_id": "turn-1"},
            )
            CandidateFormer(store).form_candidates("assistant-lesson")
            candidate = store.list_candidates("assistant-lesson")[0]
            plane = MemoryControlPlane(
                repository=root,
                control_root=root / "control_plane",
                repository_id="governance-fixture",
                policy_version="test-v1",
                allowed_subtrees=("core", "platform", "learnings", "lifecycle"),
                validators=(),
            )

            proposal = CandidateGovernanceBridge(store).prepare(
                plane,
                candidate_id=candidate["candidate_id"],
                destination="learnings/schema-migration.md",
                scope="learning",
                applies_to="codex",
                gates=self.gates(),
            )

        self.assertEqual("quarantined", proposal["disposition"])
        self.assertNotIn("provenance_invalid", proposal["reason_codes"])
        self.assertTrue(proposal["persisted"])
        self.assertTrue(proposal["may_score"])

    @staticmethod
    def gates() -> dict[str, str]:
        return {
            "prompt_injection": "pass",
            "executable_payload": "pass",
            "provenance": "pass",
            "scope": "pass",
            "stability": "pass",
            "high_stakes": "pass",
            "authority_conflict": "pass",
        }


if __name__ == "__main__":
    unittest.main()
