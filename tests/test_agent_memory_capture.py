from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

try:
    from scripts.agent_memory_system.capture import CaptureError, TranscriptCapture
    from scripts.agent_memory_system.store import AgentMemoryStore
except ImportError:
    CaptureError = TranscriptCapture = AgentMemoryStore = None  # type: ignore[assignment]


def json_line(kind: str, payload: dict, timestamp: str = "2026-08-14T08:00:00Z") -> str:
    return json.dumps(
        {"timestamp": timestamp, "type": kind, "payload": payload},
        ensure_ascii=False,
        sort_keys=True,
    )


class AgentMemoryCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertIsNotNone(AgentMemoryStore, "public capture seam is not implemented")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "private" / "agent-memory.sqlite3"
        self.transcript = self.root / "session.jsonl"
        self.store = AgentMemoryStore(self.db)
        self.capture = TranscriptCapture(self.store)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_lines(self, *lines: str) -> None:
        self.transcript.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_captures_only_user_assistant_and_tool_evidence_with_exact_provenance(self) -> None:
        user = json_line(
            "response_item",
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "我偏好的编辑器是 Zed。"}]},
        )
        assistant = json_line(
            "response_item",
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "收到。"}]},
        )
        call = json_line(
            "response_item",
            {"type": "function_call", "name": "shell", "call_id": "c1", "arguments": '{"cmd":"pwd"}'},
        )
        result = json_line(
            "response_item",
            {"type": "function_call_output", "call_id": "c1", "output": "/private/project"},
        )
        self.write_lines(
            json_line("session_meta", {"id": "s1", "base_instructions": "secret system prompt"}),
            json_line("response_item", {"type": "message", "role": "system", "content": [{"type": "input_text", "text": "system"}]}),
            json_line("response_item", {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "developer"}]}),
            json_line("response_item", {"type": "reasoning", "summary": [{"text": "hidden"}], "encrypted_content": "ciphertext"}),
            json_line("response_item", {"type": "message", "role": "user", "memory_injected": True, "content": [{"type": "input_text", "text": "[MEMORY] injected"}]}),
            user,
            assistant,
            call,
            result,
            json_line("event_msg", {"type": "agent_message", "message": "duplicate rendering"}),
        )

        receipt = self.capture.capture_jsonl("s1", self.transcript)

        self.assertEqual(10, receipt.scanned_lines)
        self.assertEqual(4, receipt.captured)
        evidence = self.store.list_evidence(session_id="s1")
        self.assertEqual(["user", "assistant", "tool_call", "tool_result"], [row["evidence_type"] for row in evidence])
        self.assertEqual([6, 7, 8, 9], [row["source_line"] for row in evidence])
        self.assertEqual(hashlib.sha256(user.encode()).hexdigest(), evidence[0]["source_line_hash"])
        self.assertEqual("我偏好的编辑器是 Zed。", evidence[0]["content"])
        serialized = json.dumps(evidence, ensure_ascii=False)
        self.assertNotIn("secret system prompt", serialized)
        self.assertNotIn("ciphertext", serialized)
        self.assertNotIn("injected", serialized)

    def test_resume_is_idempotent_and_only_captures_appended_lines(self) -> None:
        first = json_line("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "第一条"}]})
        second = json_line("response_item", {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "第二条"}]})
        self.write_lines(first)
        first_receipt = self.capture.capture_jsonl("s1", self.transcript)
        duplicate_receipt = self.capture.capture_jsonl("s1", self.transcript)
        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write(second + "\n")
        appended_receipt = self.capture.capture_jsonl("s1", self.transcript)

        self.assertEqual(1, first_receipt.captured)
        self.assertEqual(0, duplicate_receipt.captured)
        self.assertEqual(0, duplicate_receipt.scanned_lines)
        self.assertEqual(1, appended_receipt.captured)
        self.assertEqual(2, appended_receipt.checkpoint_line)
        self.assertEqual(2, len(self.store.list_evidence(session_id="s1")))
        self.assertEqual(
            appended_receipt.checkpoint_digest,
            self.store.get_checkpoint("s1", self.transcript)["prefix_digest"],
        )

    def test_malformed_tail_fails_closed_without_partial_evidence_or_checkpoint(self) -> None:
        good = json_line("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "不要部分写入"}]})
        self.transcript.write_text(good + "\n{" + "\n", encoding="utf-8")

        with self.assertRaises(CaptureError):
            self.capture.capture_jsonl("s1", self.transcript)

        self.assertEqual([], self.store.list_evidence(session_id="s1"))
        self.assertIsNone(self.store.get_checkpoint("s1", self.transcript))

    def test_changed_prefix_is_rejected_instead_of_silently_advancing_checkpoint(self) -> None:
        self.write_lines(json_line("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "原文"}]}))
        self.capture.capture_jsonl("s1", self.transcript)
        self.write_lines(
            json_line("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "篡改"}]}),
            json_line("response_item", {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "尾部"}]}),
        )

        with self.assertRaisesRegex(CaptureError, "prefix"):
            self.capture.capture_jsonl("s1", self.transcript)

        self.assertEqual(1, len(self.store.list_evidence(session_id="s1")))
        self.assertEqual(1, self.store.get_checkpoint("s1", self.transcript)["line_number"])

    def test_checkpoint_failure_rolls_back_evidence_in_same_sqlite_transaction(self) -> None:
        self.write_lines(json_line("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "事务证据"}]}))
        with sqlite3.connect(self.db) as connection:
            connection.execute(
                "CREATE TRIGGER reject_checkpoint BEFORE INSERT ON capture_checkpoints "
                "BEGIN SELECT RAISE(ABORT, 'checkpoint failure'); END"
            )

        with self.assertRaises(sqlite3.DatabaseError):
            self.capture.capture_jsonl("s1", self.transcript)

        self.assertEqual([], self.store.list_evidence(session_id="s1"))
        self.assertIsNone(self.store.get_checkpoint("s1", self.transcript))

    def test_ephemeral_progress_and_heartbeat_tool_noise_is_excluded_but_substantive_results_remain(self) -> None:
        self.write_lines(
            json_line("response_item", {"type": "function_call_output", "call_id": "p1", "output": "progress 63%"}),
            json_line("response_item", {"type": "function_call_output", "call_id": "p2", "output": "heartbeat ok"}),
            json_line("response_item", {"type": "function_call_output", "call_id": "p3", "output": "download 100%"}),
            json_line(
                "response_item",
                {"type": "function_call_output", "call_id": "r1", "output": "3 tests failed at tests/test_memory.py:42"},
            ),
        )

        receipt = self.capture.capture_jsonl("s1", self.transcript)

        evidence = self.store.list_evidence("s1")
        self.assertEqual(receipt.captured, 1)
        self.assertEqual([row["metadata"]["call_id"] for row in evidence], ["r1"])
        self.assertIn("3 tests failed", evidence[0]["content"])

    def test_duplicate_call_id_rows_are_preserved_then_dead_lettered_instead_of_mispairing(self) -> None:
        self.write_lines(
            json_line("response_item", {"type": "function_call", "name": "shell", "call_id": "same", "arguments": '{"cmd":"first"}'}),
            json_line("response_item", {"type": "function_call", "name": "shell", "call_id": "same", "arguments": '{"cmd":"second"}'}),
            json_line("response_item", {"type": "function_call_output", "call_id": "same", "output": "first-result"}),
            json_line("response_item", {"type": "function_call_output", "call_id": "same", "output": "second-result"}),
        )

        receipt = self.capture.capture_jsonl("duplicate-call", self.transcript)
        synced = self.store.ingest_offload_sync_delta("duplicate-call")

        self.assertEqual(4, receipt.captured)
        self.assertEqual(0, synced["pairs_queued"])
        self.assertEqual(4, synced["dead_lettered"])
        self.assertIsNone(self.store.next_offload_sync_pair("duplicate-call"))

    def test_trusted_transcript_root_requires_session_bound_real_file(self) -> None:
        trusted = self.root / "sessions"
        trusted.mkdir()
        bound = trusted / "rollout-s1.jsonl"
        bound.write_text(
            json_line("response_item", {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "bound"}]}) + "\n",
            encoding="utf-8",
        )
        secure = TranscriptCapture(self.store, trusted_roots=(trusted,))
        self.assertEqual(1, secure.capture_jsonl("s1", bound).captured)
        outside = self.root / "rollout-s2.jsonl"
        outside.write_text(bound.read_text(encoding="utf-8"), encoding="utf-8")
        with self.assertRaisesRegex(CaptureError, "trusted roots"):
            secure.capture_jsonl("s2", outside)
        mismatched = trusted / "rollout-other.jsonl"
        mismatched.write_text(bound.read_text(encoding="utf-8"), encoding="utf-8")
        with self.assertRaisesRegex(CaptureError, "session_id"):
            secure.capture_jsonl("s3", mismatched)

    def test_exact_replayed_message_is_deduplicated_within_a_session(self) -> None:
        line = json.dumps(
            {
                "timestamp": "2026-08-14T08:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "msg-replayed",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "以后评审先给结论，再给证据"}],
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        self.write_lines(line, line)

        receipt = self.capture.capture_jsonl("replay-session", self.transcript)

        evidence = self.store.list_evidence("replay-session")
        self.assertEqual(1, receipt.captured)
        self.assertEqual(1, receipt.duplicates)
        self.assertEqual(1, len(evidence))
        self.assertEqual(1, evidence[0]["source_line"])
        self.assertEqual(((2, 1),), receipt.duplicate_sources)

    def test_legitimate_repeated_content_with_distinct_source_event_ids_keeps_provenance(self) -> None:
        def event(identifier: str, timestamp: str) -> str:
            return json.dumps(
                {
                    "timestamp": timestamp,
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "id": identifier,
                        "role": "user",
                        "content": [{"type": "input_text", "text": "记得跑回归测试"}],
                    },
                },
                ensure_ascii=False,
                sort_keys=True,
            )

        self.write_lines(
            event("msg-first", "2026-08-14T08:00:00Z"),
            event("msg-second", "2026-08-14T09:00:00Z"),
        )

        receipt = self.capture.capture_jsonl("repeat-session", self.transcript)

        evidence = self.store.list_evidence("repeat-session")
        self.assertEqual(2, receipt.captured)
        self.assertEqual(0, receipt.duplicates)
        self.assertEqual([1, 2], [row["source_line"] for row in evidence])
        self.assertEqual(
            ["msg-first", "msg-second"],
            [row["metadata"]["source_event_id"] for row in evidence],
        )

    def test_incremental_replay_detection_does_not_rescan_all_prior_evidence(self) -> None:
        first = json.dumps(
            {
                "timestamp": "2026-08-14T08:00:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message", "id": "msg-1", "role": "user",
                    "content": [{"type": "input_text", "text": "第一条"}],
                },
            },
            ensure_ascii=False,
        )
        second = json.dumps(
            {
                "timestamp": "2026-08-14T08:01:00Z",
                "type": "response_item",
                "payload": {
                    "type": "message", "id": "msg-2", "role": "user",
                    "content": [{"type": "input_text", "text": "第二条"}],
                },
            },
            ensure_ascii=False,
        )
        self.write_lines(first)
        self.capture.capture_jsonl("indexed-session", self.transcript)
        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write(second + "\n")
        original = self.store.list_evidence
        self.store.list_evidence = lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("capture replay detection must not rescan prior evidence")
        )
        try:
            receipt = self.capture.capture_jsonl("indexed-session", self.transcript)
        finally:
            self.store.list_evidence = original

        self.assertEqual(1, receipt.captured)

    def test_resume_reads_only_the_appended_tail_and_persists_a_byte_checkpoint(self) -> None:
        first = json_line(
            "response_item",
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "第一段"}]},
        )
        second = json_line(
            "response_item",
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "第二段"}]},
        )
        self.write_lines(first)
        self.capture.capture_jsonl("stream-session", self.transcript)
        first_size = self.transcript.stat().st_size
        with self.transcript.open("a", encoding="utf-8") as handle:
            handle.write(second + "\n")

        # A resumed capture must not use Path.read_bytes(), the old O(total
        # transcript) implementation.  It should validate a bounded boundary
        # window and then stream from the durable byte offset.
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("full reread")):
            receipt = self.capture.capture_jsonl("stream-session", self.transcript)

        checkpoint = self.store.get_checkpoint("stream-session", self.transcript)
        self.assertEqual(1, receipt.scanned_lines)
        self.assertEqual(1, receipt.captured)
        self.assertGreater(checkpoint["byte_offset"], first_size)
        self.assertEqual(self.transcript.stat().st_size, checkpoint["byte_offset"])
        self.assertEqual(64, len(checkpoint["boundary_digest"]))

    def test_changed_checkpoint_boundary_is_rejected_without_reading_the_whole_prefix(self) -> None:
        self.write_lines(
            json_line(
                "response_item",
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "边界原文"}]},
            )
        )
        self.capture.capture_jsonl("boundary-session", self.transcript)
        raw = bytearray(self.transcript.read_bytes())
        raw[-2] = ord("x")
        self.transcript.write_bytes(bytes(raw))

        with self.assertRaisesRegex(CaptureError, "prefix"):
            self.capture.capture_jsonl("boundary-session", self.transcript)

        self.assertEqual(1, len(self.store.list_evidence("boundary-session")))


if __name__ == "__main__":
    unittest.main()
