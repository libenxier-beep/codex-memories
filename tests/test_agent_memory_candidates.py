from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

try:
    from scripts.agent_memory_system.candidates import CandidateFormer, CandidateJobDispatcher
    from scripts.agent_memory_system.capture import TranscriptCapture
    from scripts.agent_memory_system.store import AgentMemoryStore
except ImportError:
    CandidateFormer = CandidateJobDispatcher = TranscriptCapture = AgentMemoryStore = None  # type: ignore[assignment]


def message(text: str, line_time: str, role: str = "user") -> str:
    text_type = "input_text" if role == "user" else "output_text"
    return json.dumps(
        {
            "timestamp": line_time,
            "type": "response_item",
            "payload": {"type": "message", "role": role, "content": [{"type": text_type, "text": text}]},
        },
        ensure_ascii=False,
        sort_keys=True,
    )


class AgentMemoryCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(CandidateFormer, "public candidate seam is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = AgentMemoryStore(self.root / "agent-memory.sqlite3")
        self.capture = TranscriptCapture(self.store)
        self.former = CandidateFormer(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def capture_texts(self, session_id: str, texts: list[tuple[str, str]]) -> None:
        path = self.root / f"{session_id}.jsonl"
        path.write_text("\n".join(message(text, time) for text, time in texts) + "\n", encoding="utf-8")
        self.capture.capture_jsonl(session_id, path)

    def test_classifies_supported_memory_kinds_and_records_no_op_without_promoting(self) -> None:
        rows = [
            ("事实：我的常驻城市是上海。", "2026-08-14T08:00:00Z"),
            ("偏好：我偏好的编辑器是 Zed。", "2026-08-14T08:01:00Z"),
            ("计划：下周完成检索评测。", "2026-08-14T08:02:00Z"),
            ("临时状态：今天正在排查索引。", "2026-08-14T08:03:00Z"),
            ("工作方法：先写失败测试，再实现。", "2026-08-14T08:04:00Z"),
            ("长期原则：私人数据只使用本地模型。", "2026-08-14T08:05:00Z"),
            ("经验教训：不要在写入失败后推进 checkpoint。", "2026-08-14T08:06:00Z"),
            ("你好，今天天气不错。", "2026-08-14T08:07:00Z"),
        ]
        self.capture_texts("s1", rows)

        receipt = self.former.form_candidates("s1", now=datetime(2026, 8, 14, 9, tzinfo=timezone.utc))

        candidates = self.store.list_candidates(session_id="s1")
        self.assertEqual(8, receipt.examined)
        self.assertEqual(
            ["fact", "preference", "plan", "temporary_state", "method", "principle", "lesson", "no_op"],
            [row["memory_class"] for row in candidates],
        )
        self.assertTrue(all(row["status"] == "proposed" for row in candidates[:-1]))
        self.assertTrue(all(row["requires_authorization"] for row in candidates[:-1]))
        self.assertEqual("ignored", candidates[-1]["status"])
        self.assertFalse(candidates[-1]["requires_authorization"])
        self.assertTrue(candidates[0]["high_impact"])
        self.assertTrue(candidates[1]["high_impact"])
        self.assertTrue(candidates[5]["high_impact"])
        self.assertIsNotNone(candidates[3]["expires_at"])

    def test_candidate_source_reference_contains_exact_span_and_hashes(self) -> None:
        text = "顺便说明，偏好：我偏好的编辑器是 Zed。以后请按这个来。"
        self.capture_texts("s1", [(text, "2026-08-14T08:00:00Z")])

        self.former.form_candidates("s1")

        candidate = self.store.list_candidates(session_id="s1")[0]
        evidence = self.store.list_evidence(session_id="s1")[0]
        self.assertEqual(evidence["event_id"], candidate["source_event_id"])
        self.assertEqual(1, candidate["source_line"])
        self.assertEqual(text[candidate["span_start"] : candidate["span_end"]], candidate["source_span"])
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), candidate["source_text_hash"])
        self.assertEqual(hashlib.sha256(candidate["claim"].encode()).hexdigest(), candidate["claim_hash"])
        self.assertEqual(str((self.root / "s1.jsonl").resolve()), candidate["source_path"])

    def test_duplicate_update_conflict_and_supersede_relations_are_idempotent(self) -> None:
        self.capture_texts(
            "s1",
            [
                ("偏好：我偏好的编辑器是 VS Code。", "2026-08-14T08:00:00Z"),
                ("偏好：我偏好的编辑器是 VS Code", "2026-08-14T08:01:00Z"),
                ("更新偏好：我现在偏好的编辑器是 Zed。", "2026-08-14T08:02:00Z"),
                ("冲突说明：我不再偏好 Zed，编辑器改回 VS Code。", "2026-08-14T08:03:00Z"),
            ],
        )

        first = self.former.form_candidates("s1")
        second = self.former.form_candidates("s1")

        relations = self.store.list_relations(session_id="s1")
        relation_types = [row["relation_type"] for row in relations]
        self.assertEqual(4, first.examined)
        self.assertEqual(0, second.created)
        self.assertIn("duplicate", relation_types)
        self.assertIn("update", relation_types)
        self.assertIn("conflict", relation_types)
        self.assertGreaterEqual(relation_types.count("supersede"), 1)
        self.assertEqual(len(relations), len({row["relation_id"] for row in relations}))

        conflict_source = self.store.list_candidates("s1")[-1]["candidate_id"]
        conflict_relations = [
            row for row in relations if row["source_candidate_id"] == conflict_source
        ]
        self.assertEqual(["conflict"], [row["relation_type"] for row in conflict_relations])

    def test_explicit_deletion_request_proposes_delete_propagation_without_deleting_evidence(self) -> None:
        self.capture_texts(
            "s1",
            [("偏好：我偏好的编辑器是 VS Code。", "2026-08-14T08:00:00Z")],
        )
        self.former.form_candidates("s1")
        self.capture_texts(
            "s2",
            [("删除记忆：请忘记我偏好的编辑器。", "2026-08-14T09:00:00Z")],
        )

        self.former.form_candidates("s2")

        deletion = self.store.list_candidates(session_id="s2")[0]
        delete_relations = [
            row for row in self.store.list_relations() if row["relation_type"] == "delete"
        ]
        self.assertEqual("deletion_request", deletion["memory_class"])
        self.assertEqual("proposed", deletion["status"])
        self.assertTrue(deletion["requires_authorization"])
        self.assertTrue(deletion["high_impact"])
        self.assertEqual(1, len(delete_relations))
        self.assertEqual(deletion["candidate_id"], delete_relations[0]["source_candidate_id"])
        self.assertEqual(2, len(self.store.list_evidence()))
        self.assertEqual(2, len(self.store.list_candidates()))

    def test_generic_chinese_deletion_subject_links_all_prior_versions(self) -> None:
        self.capture_texts(
            "s1",
            [
                ("事实：仓库默认测试命令是 pytest", "2026-08-14T08:00:00Z"),
                ("事实：仓库默认测试命令是 python3 -m unittest", "2026-08-14T08:01:00Z"),
            ],
        )
        self.former.form_candidates("s1")
        self.capture_texts(
            "s2",
            [("请忘记仓库默认测试命令", "2026-08-14T09:00:00Z")],
        )

        self.former.form_candidates("s2")

        deletion = self.store.list_candidates("s2")[0]
        targets = {
            row["target_candidate_id"]
            for row in self.store.list_relations()
            if row["relation_type"] == "delete"
            and row["source_candidate_id"] == deletion["candidate_id"]
        }
        self.assertEqual(
            {row["candidate_id"] for row in self.store.list_candidates("s1")},
            targets,
        )

    def test_lifecycle_relations_follow_occurrence_order_and_exact_duplicate_wins(self) -> None:
        self.capture_texts(
            "s1",
            [
                ("更新偏好：我偏好的编辑器是 Zed", "2026-08-14T08:02:00Z"),
                ("偏好：我偏好的编辑器是 VS Code", "2026-08-14T08:00:00Z"),
                ("更新偏好：我偏好的编辑器是 VS Code", "2026-08-14T08:01:00Z"),
            ],
        )

        self.former.form_candidates("s1")

        candidates = {row["source_line"]: row for row in self.store.list_candidates("s1")}
        relations = self.store.list_relations("s1")
        duplicate = [row for row in relations if row["source_candidate_id"] == candidates[3]["candidate_id"]]
        self.assertEqual(["duplicate"], [row["relation_type"] for row in duplicate])
        zed_relations = [row for row in relations if row["source_candidate_id"] == candidates[1]["candidate_id"]]
        self.assertTrue(zed_relations)
        self.assertTrue(all(row["target_candidate_id"] == candidates[3]["candidate_id"] for row in zed_relations))

    def test_backfilled_evidence_relates_later_candidate_to_earlier_provenance(self) -> None:
        self.capture_texts(
            "late",
            [("偏好：我偏好的编辑器是 Zed", "2026-08-14T10:00:00Z")],
        )
        self.former.form_candidates("late")
        late = self.store.list_candidates("late")[0]
        self.capture_texts(
            "early",
            [("偏好：我偏好的编辑器是 VS Code", "2026-08-14T08:00:00Z")],
        )

        self.former.form_candidates("early")

        early = self.store.list_candidates("early")[0]
        relations = [
            row for row in self.store.list_relations()
            if row["source_candidate_id"] == late["candidate_id"]
        ]
        self.assertTrue(relations)
        self.assertTrue(all(row["target_candidate_id"] == early["candidate_id"] for row in relations))

    def test_natural_collaboration_statements_form_precise_candidates_without_prefixes(self) -> None:
        self.capture_texts(
            "s1",
            [
                ("仓库默认测试命令是 python3 -m unittest", "2026-08-14T08:00:00Z"),
                ("不要把私人资料放进默认上下文", "2026-08-14T08:01:00Z"),
                ("这次失败因为索引版本未校验，下次先检查 revision", "2026-08-14T08:02:00Z"),
                ("临时下载完成", "2026-08-14T08:03:00Z"),
                ("好的，谢谢", "2026-08-14T08:04:00Z"),
            ],
        )

        self.former.form_candidates("s1")

        candidates = self.store.list_candidates("s1")
        self.assertEqual(
            ["fact", "principle", "lesson", "no_op", "no_op"],
            [row["memory_class"] for row in candidates],
        )
        self.assertEqual(
            "私人资料不得进入默认上下文",
            candidates[1]["claim"],
        )
        self.assertTrue(candidates[0]["requires_authorization"])
        self.assertTrue(candidates[1]["requires_authorization"])

    def test_natural_plan_principle_and_lifecycle_slots_are_deterministic(self) -> None:
        self.capture_texts(
            "s1",
            [
                ("本周先试用字符 bigram；周五复查", "2026-08-14T08:00:00Z"),
                ("索引仅生成候选，返回前必须重开权威来源", "2026-08-14T08:01:00Z"),
                ("默认输出英文", "2026-08-14T08:02:00Z"),
                ("默认输出中文", "2026-08-14T08:03:00Z"),
                ("review 2026-08-20", "2026-08-14T08:04:00Z"),
                ("review 改到 2026-08-22", "2026-08-14T08:05:00Z"),
                ("合成配置 001=old", "2026-08-14T08:06:00Z"),
                ("合成配置 001=new", "2026-08-14T08:07:00Z"),
            ],
        )

        self.former.form_candidates("s1", now=datetime(2026, 8, 14, 9, tzinfo=timezone.utc))

        candidates = self.store.list_candidates("s1")
        self.assertEqual(
            ["plan", "principle", "preference", "preference", "plan", "plan", "fact", "fact"],
            [row["memory_class"] for row in candidates],
        )
        self.assertEqual("本周试用字符 bigram，周五复查", candidates[0]["claim"])
        self.assertEqual("2026-08-21", candidates[0]["expires_at"][:10])
        self.assertEqual("索引只生成候选；返回前重开权威来源", candidates[1]["claim"])
        self.assertEqual(candidates[2]["slot_key"], candidates[3]["slot_key"])
        self.assertEqual(candidates[4]["slot_key"], candidates[5]["slot_key"])
        self.assertEqual(candidates[6]["slot_key"], candidates[7]["slot_key"])
        relation_types = [row["relation_type"] for row in self.store.list_relations("s1")]
        self.assertGreaterEqual(relation_types.count("update"), 3)
        self.assertGreaterEqual(relation_types.count("supersede"), 3)

    def test_source_grounded_assistant_lesson_forms_a_quarantined_candidate_on_stop(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        from agent_memory import ProductionHookRuntime

        runtime = ProductionHookRuntime(
            store=self.store,
            root=ROOT,
            authority_index=self.root / "authority.sqlite",
            hybrid_index=self.root / "hybrid.sqlite",
            embedding_cache=self.root / "embedding-cache",
        )
        runtime.capture_tool_call(
            session_id="assistant-lesson", cwd=str(ROOT), turn_id="turn-lesson",
            tool_use_id="tool-1", tool_name="exec_command",
            tool_input={"cmd": "python3 -m unittest"},
        )
        runtime.capture_tool_result(
            session_id="assistant-lesson", cwd=str(ROOT), turn_id="turn-lesson",
            tool_use_id="tool-1", tool_name="exec_command",
            tool_response={"output": "old reader failed; new reader passed", "exit_code": 0},
        )

        receipt = runtime.capture_assistant(
            session_id="assistant-lesson", cwd=str(ROOT), turn_id="turn-lesson",
            content="这个 bug 最终说明 schema migration 必须同时验证新旧读路径。",
        )

        candidates = self.store.list_candidates("assistant-lesson")
        self.assertEqual(1, receipt["candidates"]["processed"])
        self.assertEqual(1, len(candidates))
        self.assertEqual("lesson", candidates[0]["memory_class"])
        self.assertEqual("proposed", candidates[0]["status"])
        self.assertTrue(candidates[0]["requires_authorization"])
        source = next(
            row for row in self.store.list_evidence("assistant-lesson")
            if row["event_id"] == candidates[0]["source_event_id"]
        )
        self.assertEqual("assistant", source["evidence_type"])

        self.store.capture_hook_observation(
            session_id="unsupported-assistant", event_name="Stop",
            evidence_type="assistant", role="assistant",
            content="这个 bug 最终说明 schema migration 必须同时验证新旧读路径。",
            cwd=str(ROOT), source_event_id="turn-without-tool",
            metadata={"turn_id": "turn-without-tool"},
        )
        self.former.form_candidates("unsupported-assistant")
        self.assertEqual([], self.store.list_candidates("unsupported-assistant"))

    def test_candidate_formation_coverage_exposes_silent_durable_signal_loss(self) -> None:
        self.capture_texts(
            "coverage",
            [("经验教训：索引迁移必须验证新旧读路径。", "2026-08-14T08:00:00Z")],
        )

        before = self.former.coverage_report(session_id="coverage")
        self.former.form_candidates("coverage")
        after = self.former.coverage_report(session_id="coverage")

        self.assertEqual(1, before["eligible_durable_signals"])
        self.assertEqual(0, before["formed_durable_signals"])
        self.assertEqual(0.0, before["candidate_formation_recall"])
        self.assertEqual(1, before["missing_durable_signals"])
        self.assertEqual(1, after["formed_durable_signals"])
        self.assertEqual(1.0, after["candidate_formation_recall"])
        self.assertEqual(0, after["missing_durable_signals"])

    def test_recovery_backfills_a_pre_upgrade_grounded_assistant_lesson(self) -> None:
        for event_name, evidence_type, content, source_id in (
            ("PreToolUse", "tool_call", '{"name":"exec_command"}', "call-old"),
            ("PostToolUse", "tool_result", "old reader failed", "result-old"),
            (
                "Stop", "assistant",
                "这个 bug 最终说明 schema migration 必须同时验证新旧读路径。",
                "turn-old",
            ),
        ):
            self.store.capture_hook_observation(
                session_id="old-session", event_name=event_name,
                evidence_type=evidence_type,
                role="assistant" if evidence_type == "assistant" else None,
                content=content, cwd=str(ROOT), source_event_id=source_id,
                metadata={
                    "turn_id": "turn-old",
                    **({"call_id": "call-old"} if evidence_type != "assistant" else {}),
                },
            )
        dispatcher = CandidateJobDispatcher(self.store)

        queued = dispatcher.enqueue_missing(session_id="old-session")
        dispatched = dispatcher.dispatch_pending(worker_id="recovery", limit=4)

        self.assertEqual(1, queued["enqueued"])
        self.assertEqual(1, dispatched["processed"])
        self.assertEqual("lesson", self.store.list_candidates("old-session")[0]["memory_class"])


if __name__ == "__main__":
    unittest.main()
