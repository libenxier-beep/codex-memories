from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest

try:
    from scripts.agent_memory_system.offload import OffloadEngine
    from scripts.agent_memory_system.reliability import LeaseConflict, PipelineReliability
    from scripts.agent_memory_system.store import AgentMemoryStore
except ImportError:
    OffloadEngine = LeaseConflict = PipelineReliability = AgentMemoryStore = None  # type: ignore[assignment]


UTC = timezone.utc


class AgentMemoryReliabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(PipelineReliability, "public reliability seam is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "private" / "agent-memory.sqlite3"
        self.store = AgentMemoryStore(self.db)
        self.pipeline = PipelineReliability(self.store)
        self.now = datetime(2026, 8, 14, 8, tzinfo=UTC)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_database_is_private_and_enqueue_is_durable_and_idempotent(self) -> None:
        first = self.pipeline.enqueue("distill", {"session_id": "s1"}, "capture:s1:4")
        second = self.pipeline.enqueue("distill", {"session_id": "s1"}, "capture:s1:4")
        reopened = PipelineReliability(AgentMemoryStore(self.db))

        self.assertEqual(first.job_id, second.job_id)
        self.assertEqual(1, len(reopened.list_jobs()))
        self.assertEqual(0o600, os.stat(self.db).st_mode & 0o777)

    def test_lease_is_owner_bound_and_completion_is_persisted(self) -> None:
        job = self.pipeline.enqueue(
            "distill", {"session_id": "s1"}, "distill:s1", now=self.now
        )
        leased = self.pipeline.lease("worker-a", now=self.now, lease_seconds=30, limit=1)

        self.assertEqual([job.job_id], [row.job_id for row in leased])
        self.assertEqual("leased", leased[0].status)
        with self.assertRaises(LeaseConflict):
            self.pipeline.complete(job.job_id, "worker-b", {"candidates": 1}, now=self.now)
        self.pipeline.complete(job.job_id, "worker-a", {"candidates": 1}, now=self.now)
        persisted = PipelineReliability(AgentMemoryStore(self.db)).list_jobs()[0]
        self.assertEqual("succeeded", persisted.status)
        self.assertEqual({"candidates": 1}, persisted.result)

    def test_failure_retries_then_moves_to_dead_letter_queue(self) -> None:
        job = self.pipeline.enqueue(
            "index", {"generation": 7}, "index:7", max_attempts=2, now=self.now
        )
        self.pipeline.lease("worker-a", now=self.now, lease_seconds=30)
        retry = self.pipeline.fail(
            job.job_id,
            "worker-a",
            "embedding_unavailable",
            "local model missing",
            now=self.now,
            retry_delay_seconds=5,
        )
        self.assertEqual("pending", retry.status)
        self.assertEqual([], self.pipeline.lease("worker-b", now=self.now + timedelta(seconds=4), lease_seconds=30))
        self.pipeline.lease("worker-b", now=self.now + timedelta(seconds=5), lease_seconds=30)
        dead = self.pipeline.fail(
            job.job_id,
            "worker-b",
            "embedding_unavailable",
            "still missing",
            now=self.now + timedelta(seconds=6),
        )

        self.assertEqual("dead", dead.status)
        letters = self.pipeline.list_dead_letters()
        self.assertEqual(1, len(letters))
        self.assertEqual(job.job_id, letters[0]["job_id"])
        self.assertEqual("embedding_unavailable", letters[0]["error_code"])

    def test_recover_requeues_expired_lease_and_dead_letters_exhausted_lease(self) -> None:
        recoverable = self.pipeline.enqueue("distill", {"session_id": "s1"}, "d:s1", max_attempts=2, now=self.now)
        exhausted = self.pipeline.enqueue("distill", {"session_id": "s2"}, "d:s2", max_attempts=1, now=self.now)
        self.pipeline.lease("crashed", now=self.now, lease_seconds=10, limit=2)

        receipt = self.pipeline.recover(now=self.now + timedelta(seconds=11))

        jobs = {row.job_id: row for row in self.pipeline.list_jobs()}
        self.assertEqual("pending", jobs[recoverable.job_id].status)
        self.assertEqual("dead", jobs[exhausted.job_id].status)
        self.assertEqual(1, receipt.requeued)
        self.assertEqual(1, receipt.dead_lettered)
        self.assertEqual(1, len(self.pipeline.list_dead_letters()))

    def test_health_detects_stalled_stage_expired_lease_dead_letter_and_records_errors(self) -> None:
        self.pipeline.heartbeat("capture", cursor="s1:12", now=self.now)
        job = self.pipeline.enqueue("distill", {"session_id": "s1"}, "stall:s1", max_attempts=1, now=self.now)
        self.pipeline.lease("crashed", now=self.now, lease_seconds=10)
        self.pipeline.record_error("capture", "invalid_jsonl", "line 13", "s1:13", now=self.now)

        report = self.pipeline.health(now=self.now + timedelta(seconds=61), stale_after_seconds=60)

        self.assertEqual("failed", report.status)
        self.assertEqual(["capture"], report.stale_stages)
        self.assertEqual([job.job_id], report.expired_leases)
        self.assertEqual("invalid_jsonl", report.recent_errors[0]["error_code"])
        recovery = self.pipeline.recover(now=self.now + timedelta(seconds=61))
        self.assertEqual(1, recovery.dead_lettered)
        after = self.pipeline.health(now=self.now + timedelta(seconds=61), stale_after_seconds=60)
        self.assertEqual(1, after.dead_jobs)

    def test_shared_store_atomically_persists_versioned_offload_bundle(self) -> None:
        engine = OffloadEngine(self.store)
        engine.start_task(
            task_id="task-local",
            goal="审计日志",
            constraints=("不得联网",),
            source_ref="session:s1:user:1",
        )
        engine.record_tool_step(
            task_id="task-local",
            step_id="step-1",
            tool_name="read_log",
            arguments={"path": "/private/log"},
            result="raw local evidence",
            source_ref="session:s1:tool-pair:2",
            summary="完成日志审计",
            expected_version=1,
        )

        reopened = AgentMemoryStore(self.db)
        snapshot = reopened.load_offload_task("task-local")
        self.assertEqual([1, 2], reopened.list_offload_versions("task-local"))
        self.assertEqual(2, snapshot["version"])
        evidence_ref = snapshot["steps"][0]["evidence_ref"]
        self.assertEqual("raw local evidence", OffloadEngine(reopened).drill_down(
            "task-local", evidence_ref, expected_version=2
        )["result"])

    def test_offload_receipt_failure_rolls_back_snapshot_and_raw_evidence(self) -> None:
        engine = OffloadEngine(self.store)
        engine.start_task(
            task_id="task-atomic",
            goal="验证事务",
            constraints=(),
            source_ref="session:s1:user:1",
        )
        with __import__("sqlite3").connect(self.db) as connection:
            connection.execute(
                "CREATE TRIGGER reject_offload_receipt BEFORE INSERT ON offload_receipts "
                "WHEN NEW.version = 2 BEGIN SELECT RAISE(ABORT, 'receipt failure'); END"
            )

        with self.assertRaises(Exception):
            engine.record_tool_step(
                task_id="task-atomic",
                step_id="step-failed",
                tool_name="read_log",
                arguments={},
                result="must roll back",
                source_ref="session:s1:tool-pair:2",
                summary="不应可见",
                expected_version=1,
            )

        self.assertEqual([1], self.store.list_offload_versions("task-atomic"))
        self.assertEqual([], [
            row for row in self.store.list_offload_versions("task-atomic") if row == 2
        ])


if __name__ == "__main__":
    unittest.main()
