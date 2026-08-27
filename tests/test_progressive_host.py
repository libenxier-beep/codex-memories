from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import os
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import progressive_host


class ProgressiveHostPublicSeamTests(unittest.TestCase):
    def test_runtime_publishes_a_host_driven_progressive_module(self) -> None:
        self.assertIsNotNone(importlib.util.find_spec("progressive_host"))

    def test_runtime_publishes_stateless_advance_seam(self) -> None:
        self.assertTrue(callable(getattr(progressive_host, "advance", None)))

    def test_runtime_publishes_durable_host_session_controller(self) -> None:
        self.assertTrue(
            callable(getattr(progressive_host, "ProgressiveSessionController", None))
        )

    def test_controller_hands_one_query_from_hook_to_current_codex_and_back(self) -> None:
        calls = []

        def fake_advance(query, *, decisions, query_id, **kwargs):
            calls.append((query, list(decisions), query_id))
            if not decisions:
                return {
                    "schema_version": "cm-progressive-host-advance-v1",
                    "status": "awaiting_decision",
                    "candidate_binding": {
                        "commit": "cb0761fcc072dac32ac20a493aa85bb46deab9e8",
                        "tree": "6c38ceedebce016ddd57829327b8898d20324530",
                    },
                    "decisions_consumed": 0,
                    "observation": {"round": 1, "visible_evidence": []},
                }
            return {
                "schema_version": "cm-progressive-host-advance-v1",
                "status": "complete",
                "candidate_binding": {
                    "commit": "cb0761fcc072dac32ac20a493aa85bb46deab9e8",
                    "tree": "6c38ceedebce016ddd57829327b8898d20324530",
                },
                "decisions_consumed": len(decisions),
                "result": {"status": "complete", "evidence": []},
            }

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "progressive"
            progressive_host.set_mode(state, "candidate")
            controller = progressive_host.ProgressiveSessionController(
                state, advance_fn=fake_advance
            )
            self.assertTrue(callable(getattr(controller, "start", None)))
            self.assertTrue(callable(getattr(controller, "show", None)))
            self.assertTrue(callable(getattr(controller, "step", None)))
            started = controller.start(
                query="Use my memory to plan this week",
                codex_session_id="codex-session-1",
                allowed_scopes=("personal",),
            )
            shown = controller.show(started["session_token"])
            completed = controller.step(
                started["session_token"],
                {
                    "evidence_status": "complete",
                    "missing_facets": [],
                    "confidence": 0.9,
                    "actions": [],
                    "final_evidence_ids": [],
                    "stop_reason": "sufficient_evidence",
                },
            )
            session_file = state / "sessions" / (started["session_token"] + ".json")

            self.assertEqual("awaiting_decision", started["status"])
            self.assertEqual(started["session_token"], shown["session_token"])
            self.assertEqual("complete", completed["status"])
            self.assertEqual(3, len(calls))
            self.assertEqual([], calls[0][1])
            self.assertEqual(["personal"], __import__("json").loads(session_file.read_text())["allowed_scopes"])
            self.assertEqual([], calls[1][1])
            self.assertEqual(1, len(calls[2][1]))
            self.assertEqual(0o600, session_file.stat().st_mode & 0o777)

    def test_start_removes_owner_only_sessions_older_than_one_day(self) -> None:
        def fake_advance(query, *, decisions, query_id, **kwargs):
            return {
                "status": "awaiting_decision",
                "candidate_binding": {
                    "commit": "cb0761fcc072dac32ac20a493aa85bb46deab9e8",
                    "tree": "6c38ceedebce016ddd57829327b8898d20324530",
                },
                "observation": {"visible_evidence": []},
            }

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "progressive"
            progressive_host.set_mode(state, "candidate")
            sessions = state / "sessions"
            sessions.mkdir(mode=0o700)
            stale = sessions / ("b" * 32 + ".json")
            stale.write_text("{}", encoding="utf-8")
            stale.chmod(0o600)
            old = time.time() - 90_000
            os.utime(stale, (old, old))
            controller = progressive_host.ProgressiveSessionController(
                state, advance_fn=fake_advance
            )

            controller.start(
                query="fresh query",
                codex_session_id="session",
                allowed_scopes=("work",),
            )

            self.assertFalse(stale.exists())

    def test_advance_bootstraps_then_yields_a_typed_observation_to_current_codex(self) -> None:
        try:
            import progressive_knowledge_access as progressive
        except ImportError:
            self.fail("the frozen progressive engine is not installed in the runtime")

        class SeedHost:
            def execute(self, action, request, allowance):
                return progressive.ToolResult(
                    status="ok",
                    candidates=(
                        progressive.CandidateEvidence(
                            candidate_id="seed",
                            evidence_group_id="group-seed",
                            summary="Seed summary",
                            body="Seed body",
                            authorization_handles=("auth:seed",),
                            authority=progressive.AuthorityReceipt(
                                path="core/seed.md",
                                source_revision="a" * 40,
                                source_sha256="b" * 64,
                                locator="section:1;chars:0-9",
                                verified=True,
                            ),
                        ),
                    ),
                )

        result = progressive_host.advance(
            "Where is the current seed?",
            decisions=[],
            host=SeedHost(),
            query_id="dogfood-seed",
        )

        self.assertEqual("awaiting_decision", result["status"])
        self.assertEqual(1, result["observation"]["round"])
        self.assertEqual("seed", result["observation"]["visible_evidence"][0]["candidate_id"])
        self.assertEqual(["auth:seed"], result["observation"]["available_authorization_handles"])

    def test_current_codex_can_finish_the_same_replayed_session_with_typed_evidence(self) -> None:
        import progressive_knowledge_access as progressive

        class SeedHost:
            def execute(self, action, request, allowance):
                return progressive.ToolResult(
                    status="ok",
                    candidates=(
                        progressive.CandidateEvidence(
                            candidate_id="seed",
                            evidence_group_id="group-seed",
                            summary="Current seed",
                            body="The current seed is B.",
                            authority=progressive.AuthorityReceipt(
                                path="core/seed.md",
                                source_revision="a" * 40,
                                source_sha256="b" * 64,
                                locator="section:1;chars:0-22",
                                verified=True,
                            ),
                        ),
                    ),
                )

        result = progressive_host.advance(
            "What is the current seed?",
            decisions=[
                {
                    "evidence_status": "complete",
                    "missing_facets": [],
                    "confidence": 0.91,
                    "actions": [],
                    "final_evidence_ids": ["seed"],
                    "stop_reason": "sufficient_evidence",
                }
            ],
            host=SeedHost(),
            query_id="dogfood-seed",
        )

        self.assertEqual("complete", result["status"])
        self.assertEqual("complete", result["result"]["status"])
        self.assertEqual("seed", result["result"]["evidence"][0]["candidate_id"])
        self.assertEqual(1, result["result"]["budget"]["rounds_used"])
        self.assertIn("candidate_binding", result)
        self.assertEqual(
            "cb0761fcc072dac32ac20a493aa85bb46deab9e8",
            result["candidate_binding"]["commit"],
        )
        self.assertEqual(
            "6c38ceedebce016ddd57829327b8898d20324530",
            result["candidate_binding"]["tree"],
        )


if __name__ == "__main__":
    unittest.main()
