from __future__ import annotations

from datetime import datetime, timezone
import unittest

from scripts.agent_memory_system.lifecycle import LifecycleResolver


class LifecycleResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.resolver = LifecycleResolver()
        self.now = datetime(2026, 8, 14, tzinfo=timezone.utc)

    def test_relations_select_one_active_candidate_without_authorizing_it(self) -> None:
        candidates = [
            {"candidate_id": "c-old", "status": "proposed", "memory_class": "preference"},
            {"candidate_id": "c-new", "status": "proposed", "memory_class": "preference"},
            {"candidate_id": "c-copy", "status": "proposed", "memory_class": "preference"},
        ]
        relations = [
            {"relation_type": "update", "source_candidate_id": "c-new", "target_candidate_id": "c-old"},
            {"relation_type": "supersede", "source_candidate_id": "c-new", "target_candidate_id": "c-old"},
            {"relation_type": "duplicate", "source_candidate_id": "c-copy", "target_candidate_id": "c-new"},
        ]

        result = self.resolver.resolve(
            candidates=candidates,
            relations=relations,
            external_ids={"c-old": "m1", "c-new": "e1", "c-copy": "e2"},
            incoming_ids={"e1", "e2"},
            metadata={},
            now=self.now,
        )

        self.assertEqual(["e1"], result.active)
        self.assertIn({"op": "update", "target": "m1", "by": "e1"}, result.actions)
        self.assertIn({"op": "supersede", "target": "m1", "by": "e1"}, result.actions)
        self.assertIn({"op": "deduplicate", "target": "e2", "into": "e1"}, result.actions)
        self.assertFalse(result.deletion_propagated)

    def test_tombstone_and_expiry_propagate_and_suppress_descendants(self) -> None:
        result = self.resolver.resolve(
            candidates=[
                {"candidate_id": "c-old", "status": "proposed", "memory_class": "temporary_state"},
                {"candidate_id": "c-new", "status": "proposed", "memory_class": "fact"},
            ],
            relations=[
                {"relation_type": "update", "source_candidate_id": "c-new", "target_candidate_id": "c-old"}
            ],
            external_ids={"c-old": "m2", "c-new": "e3"},
            incoming_ids={"e3"},
            metadata={
                "records": {"m2": {"expires_at": "2026-08-13"}},
                "tombstones": {"m2"},
                "delete_source": "e-old",
            },
            now=self.now,
        )

        self.assertIn({"op": "expire", "target": "m2"}, result.actions)
        self.assertIn({"op": "tombstone", "target": "m2"}, result.actions)
        self.assertIn(
            {"op": "suppress_candidate", "target": "e3", "reason": "deleted_lineage"},
            result.actions,
        )
        self.assertIn({"op": "propagate_delete", "target": "e-old"}, result.actions)
        self.assertEqual([], result.active)
        self.assertEqual(["m2"], result.expired)
        self.assertTrue(result.deletion_propagated)

    def test_resolve_store_is_a_product_seam_and_expiry_is_inclusive(self) -> None:
        from pathlib import Path
        import json
        import tempfile

        from scripts.agent_memory_system.candidates import CandidateFormer
        from scripts.agent_memory_system.capture import TranscriptCapture
        from scripts.agent_memory_system.store import AgentMemoryStore

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = AgentMemoryStore(root / "state.sqlite")
            transcript = root / "session.jsonl"
            transcript.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-08-13T00:00:00Z",
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "user",
                            "content": [{"type": "input_text", "text": "临时状态：今天排查索引"}],
                        },
                    },
                    ensure_ascii=False,
                ) + "\n",
                encoding="utf-8",
            )
            TranscriptCapture(store).capture_jsonl("s1", transcript)
            CandidateFormer(store).form_candidates("s1")
            # Store-backed resolution must be callable by the CLI/runtime and
            # must not require a harness-owned external ID translation.
            result = self.resolver.resolve_store(store, now=self.now)
            identifier = store.list_candidates("s1")[0]["candidate_id"]

        self.assertEqual([identifier], result.expired)
        self.assertIn({"op": "expire", "target": identifier}, result.actions)

    def test_session_resolution_reopens_cross_session_relation_targets(self) -> None:
        from pathlib import Path
        import json
        import tempfile

        from scripts.agent_memory_system.candidates import CandidateFormer
        from scripts.agent_memory_system.capture import TranscriptCapture
        from scripts.agent_memory_system.store import AgentMemoryStore

        def line(text: str, stamp: str) -> str:
            return json.dumps(
                {
                    "timestamp": stamp,
                    "type": "response_item",
                    "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]},
                },
                ensure_ascii=False,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = AgentMemoryStore(root / "state.sqlite")
            first = root / "first.jsonl"
            first.write_text(line("事实：仓库默认测试命令是 pytest", "2026-08-14T08:00:00Z") + "\n", encoding="utf-8")
            TranscriptCapture(store).capture_jsonl("s1", first)
            CandidateFormer(store).form_candidates("s1")
            target = store.list_candidates("s1")[0]["candidate_id"]
            second = root / "second.jsonl"
            second.write_text(line("请忘记仓库默认测试命令", "2026-08-14T09:00:00Z") + "\n", encoding="utf-8")
            TranscriptCapture(store).capture_jsonl("s2", second)
            CandidateFormer(store).form_candidates("s2")

            result = self.resolver.resolve_store(store, session_id="s2", now=self.now)

        self.assertIn({"op": "propagate_delete", "target": target}, result.actions)

    def test_valid_to_is_exclusive_and_expires_at_the_exact_boundary(self) -> None:
        result = self.resolver.resolve(
            candidates=[],
            relations=[],
            external_ids={},
            incoming_ids=set(),
            metadata={"records": {"m-boundary": {"expires_at": "2026-08-14T00:00:00Z"}}},
            now=self.now,
        )

        self.assertEqual(["m-boundary"], result.expired)
        self.assertIn({"op": "expire", "target": "m-boundary"}, result.actions)

    def test_untrusted_conflict_is_quarantined_without_superseding_existing(self) -> None:
        result = self.resolver.resolve(
            candidates=[
                {"candidate_id": "old", "status": "proposed", "memory_class": "fact"},
                {"candidate_id": "incoming", "status": "proposed", "memory_class": "fact"},
            ],
            relations=[
                {"relation_type": "conflict", "source_candidate_id": "incoming", "target_candidate_id": "old"}
            ],
            external_ids={"old": "memory-old", "incoming": "proposal-new"},
            incoming_ids={"proposal-new"},
            metadata={},
            now=self.now,
        )

        self.assertEqual([], result.active)
        self.assertEqual(
            [{"op": "conflict", "target": "memory-old", "by": "proposal-new"}],
            result.actions,
        )

    def test_tombstoned_target_blocks_update_actions_before_relation_processing(self) -> None:
        result = self.resolver.resolve(
            candidates=[
                {"candidate_id": "old", "status": "proposed", "memory_class": "fact"},
                {"candidate_id": "incoming", "status": "proposed", "memory_class": "fact"},
            ],
            relations=[
                {"relation_type": "update", "source_candidate_id": "incoming", "target_candidate_id": "old"},
                {"relation_type": "supersede", "source_candidate_id": "incoming", "target_candidate_id": "old"},
            ],
            external_ids={"old": "memory-old", "incoming": "proposal-new"},
            incoming_ids={"proposal-new"},
            metadata={"tombstones": {"memory-old"}},
            now=self.now,
        )

        self.assertEqual([], result.active)
        self.assertNotIn("update", {action["op"] for action in result.actions})
        self.assertNotIn("supersede", {action["op"] for action in result.actions})
        self.assertIn(
            {"op": "suppress_candidate", "target": "proposal-new", "reason": "deleted_lineage"},
            result.actions,
        )


if __name__ == "__main__":
    unittest.main()
