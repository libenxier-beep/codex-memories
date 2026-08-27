from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from agent_memory_system.offload import OffloadEngine, OffloadError  # noqa: E402


class RecordingOffloadStore:
    """Executable adapter for the documented atomic offload store seam."""

    def __init__(self) -> None:
        self.tasks: dict[str, dict[int, dict[str, object]]] = {}
        self.evidence: dict[str, dict[str, object]] = {}
        self.receipts: list[dict[str, object]] = []
        self.fail_before_commit = False

    def commit_offload_bundle(self, bundle: dict[str, object]) -> dict[str, object]:
        if self.fail_before_commit:
            raise RuntimeError("injected atomic failure")
        snapshot = copy.deepcopy(bundle["snapshot"])
        task_id = str(snapshot["task_id"])
        version = int(snapshot["version"])
        expected_version = int(bundle["expected_version"])
        versions = self.tasks.setdefault(task_id, {})
        current = max(versions, default=0)
        if current != expected_version:
            raise RuntimeError("optimistic version conflict")
        staged_evidence = {
            str(item["evidence_ref"]): copy.deepcopy(item)
            for item in bundle["evidence"]
        }
        receipt = copy.deepcopy(bundle["receipt"])
        # The fake mutates only after all validation, mirroring the shared store's
        # required transaction boundary.
        self.evidence.update(staged_evidence)
        versions[version] = snapshot
        self.receipts.append(receipt)
        return receipt

    def load_offload_task(
        self, task_id: str, version: int | None = None
    ) -> dict[str, object] | None:
        versions = self.tasks.get(task_id, {})
        if not versions:
            return None
        selected = max(versions) if version is None else version
        value = versions.get(selected)
        return copy.deepcopy(value) if value is not None else None

    def load_offload_evidence(self, evidence_ref: str) -> dict[str, object] | None:
        value = self.evidence.get(evidence_ref)
        return copy.deepcopy(value) if value is not None else None

    def list_offload_versions(self, task_id: str) -> list[int]:
        return sorted(self.tasks.get(task_id, {}))

    def restore_offload_evidence(self, evidence) -> bool:
        reference = str(evidence["evidence_ref"])
        if reference in self.evidence:
            return False
        self.evidence[reference] = copy.deepcopy(dict(evidence))
        return True


class AgentMemoryOffloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = RecordingOffloadStore()
        self.engine = OffloadEngine(self.store)

    def start_task(self) -> dict[str, object]:
        return self.engine.start_task(
            task_id="task-audit",
            goal="审计三份日志",
            constraints=("不得联网", "保留原始证据"),
            source_ref="session:s1:user:1",
        )

    def test_tool_pair_is_committed_with_immutable_hash_ref_and_drills_down(self) -> None:
        self.start_task()

        receipt = self.engine.record_tool_step(
            task_id="task-audit",
            step_id="step-1",
            tool_name="read_log",
            arguments={"path": "/private/a.log"},
            result="ERROR none\n47 records checked",
            source_ref="session:s1:tool-pair:17",
            summary="日志段一已审计，未发现错误",
            expected_version=1,
        )

        snapshot = self.store.load_offload_task("task-audit")
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(snapshot["version"], 2)
        self.assertEqual(len(snapshot["steps"]), 1)
        step = snapshot["steps"][0]
        self.assertRegex(step["evidence_ref"], r"^sha256:[0-9a-f]{64}$")
        self.assertIn("source:session:s1:tool-pair:17", step["summary"])

        pair = self.engine.drill_down(
            "task-audit", step["evidence_ref"], expected_version=2
        )
        self.assertEqual(pair["call"]["tool_name"], "read_log")
        self.assertEqual(pair["call"]["arguments"], {"path": "/private/a.log"})
        self.assertEqual(pair["result"], "ERROR none\n47 records checked")
        self.assertEqual(pair["source_ref"], "session:s1:tool-pair:17")

    def test_task_graph_records_dependencies_and_rejects_unknown_parents(self) -> None:
        self.start_task()
        self.engine.record_tool_step(
            task_id="task-audit",
            step_id="collect",
            tool_name="find_logs",
            arguments={},
            result="a.log b.log",
            source_ref="session:s1:tool-pair:1",
            summary="已定位日志",
            expected_version=1,
        )
        self.engine.record_tool_step(
            task_id="task-audit",
            step_id="audit-a",
            tool_name="read_log",
            arguments={"path": "a.log"},
            result="clean",
            source_ref="session:s1:tool-pair:2",
            summary="A 日志已审计",
            depends_on=("collect",),
            expected_version=2,
        )

        snapshot = self.store.load_offload_task("task-audit", 3)
        self.assertEqual(snapshot["steps"][1]["depends_on"], ["collect"])
        self.assertEqual(
            snapshot["task_graph"],
            {"collect": [], "audit-a": ["collect"]},
        )
        injection = self.engine.build_injection(
            "task-audit", expected_version=3, max_chars=1200
        )
        projection = json.loads(injection.split("\n", 1)[1])
        self.assertRegex(projection["steps"][0]["step_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(1, len(projection["steps"][0].get("depends_on")))
        self.assertRegex(
            projection["steps"][0]["depends_on"][0], r"^sha256:[0-9a-f]{64}$"
        )
        with self.assertRaises(OffloadError) as raised:
            self.engine.record_tool_step(
                task_id="task-audit",
                step_id="publish",
                tool_name="write_report",
                arguments={},
                result="report",
                source_ref="session:s1:tool-pair:3",
                summary="报告已生成",
                depends_on=("missing-step",),
                expected_version=3,
            )
        self.assertEqual(raised.exception.code, "task_dependency_missing")

    def test_missing_or_corrupt_raw_evidence_fails_closed(self) -> None:
        self.start_task()
        self.engine.record_tool_step(
            task_id="task-audit",
            step_id="step-1",
            tool_name="read_log",
            arguments={},
            result="original",
            source_ref="session:s1:tool-pair:1",
            summary="已读",
            expected_version=1,
        )
        snapshot = self.store.load_offload_task("task-audit")
        ref = snapshot["steps"][0]["evidence_ref"]
        self.store.evidence[ref]["payload"] = "corrupt"

        with self.assertRaisesRegex(OffloadError, "integrity"):
            self.engine.drill_down("task-audit", ref, expected_version=2)

    def test_missing_raw_evidence_can_only_be_restored_from_its_exact_hash_object(self) -> None:
        self.start_task()
        self.engine.record_tool_step(
            task_id="task-audit", step_id="step-1", tool_name="read_log",
            arguments={}, result="immutable raw", source_ref="session:s1:tool-pair:1",
            summary="saved", expected_version=1,
        )
        snapshot = self.store.load_offload_task("task-audit", 2)
        reference = snapshot["steps"][0]["evidence_ref"]
        saved = copy.deepcopy(self.store.evidence.pop(reference))

        restored = self.engine.restore_evidence(
            "task-audit", saved, expected_version=2
        )

        self.assertEqual("immutable raw", restored["result"])
        tampered = copy.deepcopy(saved)
        tampered["payload"] = str(tampered["payload"])[::-1]
        self.store.evidence.pop(reference)
        with self.assertRaises(OffloadError):
            self.engine.restore_evidence("task-audit", tampered, expected_version=2)

    def test_atomic_store_failure_leaves_no_snapshot_evidence_or_receipt(self) -> None:
        self.start_task()
        self.store.fail_before_commit = True

        with self.assertRaisesRegex(OffloadError, "atomic offload commit failed"):
            self.engine.record_tool_step(
                task_id="task-audit",
                step_id="step-failed",
                tool_name="read_log",
                arguments={"path": "/private/b.log"},
                result="partial bytes that must not become visible",
                source_ref="session:s1:tool-pair:18",
                summary="不应提交",
                expected_version=1,
            )

        self.assertEqual(self.store.list_offload_versions("task-audit"), [1])
        self.assertEqual(self.store.evidence, {})
        self.assertEqual(len(self.store.receipts), 1)  # the start receipt only

    def test_exact_version_is_required_and_corrupt_raw_evidence_fails_closed(self) -> None:
        self.start_task()
        self.engine.record_tool_step(
            task_id="task-audit",
            step_id="step-1",
            tool_name="read_log",
            arguments={},
            result="trusted raw",
            source_ref="session:s1:tool-pair:17",
            summary="完成",
            expected_version=1,
        )
        ref = self.store.load_offload_task("task-audit", 2)["steps"][0]["evidence_ref"]

        with self.assertRaisesRegex(OffloadError, "requested task version") as stale:
            self.engine.build_injection("task-audit", expected_version=3, max_chars=1000)
        self.assertEqual(stale.exception.code, "stale_task_version")

        payload = self.store.evidence[ref]["payload"]
        pivot = len(payload) // 2
        replacement = "A" if payload[pivot] != "A" else "B"
        self.store.evidence[ref]["payload"] = payload[:pivot] + replacement + payload[pivot + 1 :]
        with self.assertRaisesRegex(OffloadError, "integrity") as corrupt:
            self.engine.drill_down("task-audit", ref, expected_version=2)
        self.assertEqual(corrupt.exception.code, "evidence_corrupt")

    def test_versioned_injection_is_bounded_source_cited_and_replayable(self) -> None:
        self.start_task()
        self.engine.record_tool_step(
            task_id="task-audit",
            step_id="step-1",
            tool_name="read_log",
            arguments={"path": "/private/a.log"},
            result="47 records checked",
            source_ref="session:s1:tool-pair:17",
            summary="日志段一已审计",
            expected_version=1,
        )
        self.engine.update_task(
            task_id="task-audit",
            state="blocked",
            current_step_id="step-2",
            status_summary="等待第二份日志解锁",
            source_ref="session:s1:user:19",
            expected_version=2,
        )

        injection = self.engine.build_injection(
            "task-audit", expected_version=3, max_chars=750
        )
        self.assertLessEqual(len(injection), 750)
        projection = json.loads(injection.split("\n", 1)[1])
        self.assertRegex(projection["task_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(3, projection["version"])
        self.assertEqual("blocked", projection["state"])
        self.assertRegex(projection["current_step_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(projection["steps"][0]["evidence_ref"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("不得联网", injection)
        self.assertNotIn("等待第二份日志", injection)

        replay = self.engine.replay("task-audit", expected_version=3)
        self.assertEqual(replay["snapshot"]["version"], 3)
        self.assertEqual(replay["evidence"][0]["result"], "47 records checked")
        self.assertEqual(replay["integrity"], "verified")

    def test_graded_compaction_preserves_constraints_recent_messages_and_tool_pairs(self) -> None:
        self.start_task()
        for number in (1, 2):
            self.engine.record_tool_step(
                task_id="task-audit",
                step_id="step-{}".format(number),
                tool_name="read_log",
                arguments={"part": number},
                result=("raw-result-{} ".format(number) * 150),
                source_ref="session:s1:tool-pair:{}".format(number),
                summary="日志段{}已审计".format(number),
                expected_version=number,
            )
        snapshot = self.store.load_offload_task("task-audit", 3)
        first_ref = snapshot["steps"][0]["evidence_ref"]
        second_ref = snapshot["steps"][1]["evidence_ref"]
        messages = [
            {"kind": "user", "content": "不得联网", "constraint": True},
            {"kind": "tool_call", "tool_call_id": "call-1", "content": "read 1", "evidence_ref": first_ref},
            {"kind": "tool_result", "tool_call_id": "call-1", "content": "x" * 1800, "evidence_ref": first_ref},
            {"kind": "assistant", "content": "继续审计"},
            {"kind": "tool_call", "tool_call_id": "call-2", "content": "read 2", "evidence_ref": second_ref},
            {"kind": "tool_result", "tool_call_id": "call-2", "content": "y" * 1800, "evidence_ref": second_ref},
            {"kind": "user", "content": "最新约束：不要更改原文件", "constraint": True},
        ]

        compacted = self.engine.compact_context(
            "task-audit",
            messages,
            expected_version=3,
            target_chars=900,
            recent_messages=1,
        )

        self.assertEqual(compacted["level"], "emergency")
        self.assertNotIn("不得联网", compacted["injection"])
        self.assertEqual("不得联网", compacted["messages"][0]["content"])
        self.assertEqual(compacted["messages"][-1]["content"], "最新约束：不要更改原文件")
        tool_ids = [
            item.get("tool_call_id")
            for item in compacted["messages"]
            if item.get("kind") in {"tool_call", "tool_result"}
        ]
        self.assertNotIn("call-1", tool_ids)
        self.assertNotIn("call-2", tool_ids)
        self.assertEqual(
            {item["evidence_ref"] for item in compacted["messages"] if item["kind"] == "offload_summary"},
            {first_ref, second_ref},
        )
        self.assertGreater(compacted["token_reduction_ratio"], 0.65)

    def test_incomplete_or_unreferenced_tool_pair_is_never_destructively_compacted(self) -> None:
        self.start_task()
        orphan = [
            {"kind": "tool_call", "tool_call_id": "call-orphan", "content": "read"},
            {"kind": "user", "content": "next"},
        ]
        with self.assertRaises(OffloadError) as raised:
            self.engine.compact_context(
                "task-audit",
                orphan,
                expected_version=1,
                target_chars=10,
            )
        self.assertEqual(raised.exception.code, "tool_pair_incomplete")

        unreferenced = [
            {"kind": "tool_call", "tool_call_id": "call-raw", "content": "read"},
            {"kind": "tool_result", "tool_call_id": "call-raw", "content": "raw" * 100},
        ]
        result = self.engine.compact_context(
            "task-audit",
            unreferenced,
            expected_version=1,
            target_chars=10,
        )
        self.assertEqual(result["messages"], unreferenced)
        self.assertEqual(result["degraded_reason"], "unreferenced_tool_evidence")


if __name__ == "__main__":
    unittest.main()
