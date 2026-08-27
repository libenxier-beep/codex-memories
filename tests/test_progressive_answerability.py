from __future__ import annotations

import importlib
import hashlib
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import progressive_knowledge_access as progressive  # noqa: E402


class ScriptedPlanner:
    def __init__(self, decisions):
        self.decisions = list(decisions)

    def plan(self, observation):
        return self.decisions.pop(0)


def verified_candidate(
    candidate_id="target",
    *,
    body="The current replacement is record B.",
    handles=(),
):
    return progressive.CandidateEvidence(
        candidate_id=candidate_id,
        evidence_group_id=f"entity:{candidate_id}",
        summary="Replacement evidence.",
        body=body,
        authorization_handles=tuple(handles),
        authority=progressive.AuthorityReceipt(
            path=f"work_contexts/private/{candidate_id}.md",
            source_revision="a" * 40,
            source_sha256="b" * 64,
            locator="section:2;chars:40-76",
            verified=True,
        ),
    )


class DirectHost:
    def __init__(self, *, body="The current replacement is record B."):
        self.body = body
        self.calls = 0

    def execute(self, action, request, allowance):
        self.calls += 1
        return progressive.ToolResult(
            status="ok",
            candidates=(verified_candidate(body=self.body),),
        )


class ChainedRelationHost:
    def __init__(self, answerability, *, bad_commitment=False):
        self.answerability = answerability
        self.bad_commitment = bad_commitment
        self.calls = 0

    def _edge(self, edge_id, source, target, order):
        commitment = self.answerability.authority_commitment(
            "observed_relation",
            edge_id,
            source,
            target,
            "ordered_relation",
            order,
            True,
        )
        if self.bad_commitment:
            commitment = "0" * 64
        return progressive.ObservedEvidenceRelation(
            edge_id=edge_id,
            from_candidate_id=source,
            to_candidate_id=target,
            edge_type="ordered_relation",
            order=order,
            authority_commitment_sha256=commitment,
            host_authority_reopened=True,
        )

    def execute(self, action, request, allowance):
        self.calls += 1
        if action.kind == "search":
            return progressive.ToolResult(
                status="ok",
                candidates=(
                    progressive.CandidateEvidence(
                        candidate_id="seed",
                        evidence_group_id="entity:seed",
                        summary="seed",
                        body="Seed entity.",
                        authorization_handles=("auth:hop-1",),
                    ),
                ),
            )
        if action.authorization_handle == "auth:hop-1":
            return progressive.ToolResult(
                status="ok",
                candidates=(
                    progressive.CandidateEvidence(
                        candidate_id="middle",
                        evidence_group_id="entity:middle",
                        summary="middle",
                        body="Intermediate entity.",
                        authorization_handles=("auth:hop-2",),
                    ),
                ),
                observed_relations=(self._edge("edge-1", "seed", "middle", 1),),
            )
        if action.authorization_handle == "auth:hop-2":
            return progressive.ToolResult(
                status="ok",
                candidates=(verified_candidate("target"),),
                observed_relations=(self._edge("edge-2", "middle", "target", 2),),
            )
        return progressive.ToolResult(
            status="denied", candidates=(), error_code="unknown_handle"
        )


class UnboundRelationHost:
    """Returns a relation target but no exact-reopened typed edge."""

    def execute(self, action, request, allowance):
        if action.kind == "search":
            return progressive.ToolResult(
                status="ok",
                candidates=(
                    progressive.CandidateEvidence(
                        candidate_id="seed",
                        evidence_group_id="entity:seed",
                        summary="seed",
                        body="Advisory graph source.",
                        authorization_handles=("auth:advisory",),
                    ),
                ),
            )
        return progressive.ToolResult(
            status="ok",
            candidates=(verified_candidate("target"),),
            observed_relations=(),
        )


def completion_flip_planner(final_id="target"):
    return ScriptedPlanner(
        [
            progressive.PlannerDecision(
                evidence_status="missing_evidence",
                missing_facets=("current replacement",),
                confidence=0.4,
                actions=(),
            ),
            progressive.PlannerDecision(
                evidence_status="complete",
                missing_facets=(),
                confidence=0.95,
                actions=(),
                final_evidence_ids=(final_id,),
                stop_reason="sufficient_evidence",
            ),
        ]
    )


def supported_decision(ref="N1", *, probability=0.98):
    return {
        "request_objective_status": "concrete",
        "request_objective": "the current replacement record",
        "p_answerable": probability,
        "decision_confidence": 0.99,
        "facet_assessments": [
            {
                "facet": "current replacement record",
                "assessment": "supported",
                "evidence_refs": [ref],
            }
        ],
        "missing_facets": [],
        "reason_code": "complete_support",
    }


def unsupported_decision(*, underspecified=False):
    return {
        "request_objective_status": (
            "underspecified" if underspecified else "concrete"
        ),
        "request_objective": (
            "no concrete proposition" if underspecified else "the requested fact"
        ),
        "p_answerable": 0.1,
        "decision_confidence": 0.99,
        "facet_assessments": [
            {
                "facet": "the requested fact",
                "assessment": "unsupported",
                "evidence_refs": [],
            }
        ],
        "missing_facets": ["the requested fact"],
        "reason_code": (
            "instruction_only" if underspecified else "required_facet_unsupported"
        ),
    }


class ProgressiveAnswerabilityTests(unittest.TestCase):
    def _answerability(self):
        try:
            return importlib.import_module("progressive_answerability")
        except ModuleNotFoundError:
            self.fail("progressive_answerability production seam is missing")

    def _verifier(self, complete, **overrides):
        answerability = self._answerability()

        def bound_complete(request):
            return complete(request.payload)

        return answerability.StructuredAnswerabilityVerifier(
            complete=bound_complete,
            model_id="local-fixture",
            parameters={"temperature": 0},
            **overrides,
        )

    def _run_direct(self, complete, **overrides):
        verifier = self._verifier(
            complete,
            **overrides.pop("verifier_options", {}),
        )
        options = {
            "query": "What is the current replacement record?",
            "enabled": True,
            "planner": completion_flip_planner(),
            "host": DirectHost(),
            "query_id": "query-direct",
            "language": "en",
            "allowed_scopes": ("work",),
            "answerability_verifier": verifier,
        }
        options.update(overrides)
        return progressive.progressive_access_knowledge(**options)

    def test_trigger_policy_exactly_matches_frozen_completion_flip_rule(self):
        answerability = self._answerability()
        trace = [
            {
                "evidence_status": "missing_evidence",
                "actions": [],
                "new_candidate_ids": ["target"],
            },
            {
                "evidence_status": "complete",
                "actions": [],
                "new_candidate_ids": [],
            },
        ]

        self.assertTrue(
            answerability.should_trigger_verifier(trace)
        )
        for changed in (
            {"prior": "complete"},
            {"terminal": "missing_evidence"},
            {"actions": ["search"]},
            {"new_candidate_ids": ["late"]},
        ):
            candidate = json.loads(json.dumps(trace))
            candidate[0]["evidence_status"] = changed.get("prior", "missing_evidence")
            candidate[1]["evidence_status"] = changed.get("terminal", "complete")
            candidate[1]["actions"] = changed.get("actions", [])
            candidate[1]["new_candidate_ids"] = changed.get(
                "new_candidate_ids", []
            )
            self.assertFalse(
                answerability.should_trigger_verifier(
                    candidate,
                )
            )

    def test_trigger_policy_matches_the_frozen_public_cases(self):
        answerability = self._answerability()
        variants = [
            [
                {"evidence_status": "missing_evidence", "actions": [], "new_candidate_ids": []},
                {"evidence_status": "complete", "actions": [], "new_candidate_ids": []},
            ],
            [
                {"evidence_status": "missing_evidence", "actions": [], "new_candidate_ids": []},
                {"evidence_status": "complete", "actions": ["search"], "new_candidate_ids": []},
            ],
            [
                {"evidence_status": "complete", "actions": [], "new_candidate_ids": []},
                {"evidence_status": "complete", "actions": [], "new_candidate_ids": []},
            ],
        ]
        self.assertEqual(
            [answerability.should_trigger_verifier(rounds) for rounds in variants],
            [True, False, False],
        )

    def test_production_prompt_and_contract_match_the_frozen_h3_bytes(self):
        answerability = self._answerability()
        self.assertEqual(
            hashlib.sha256(answerability.H3_CONTRACT.encode("utf-8")).hexdigest(),
            "d7c933e60585082c457508a50e0bce32e19a5ecf769f5de8d000d95751ae68af",
        )
        self.assertEqual(
            hashlib.sha256(
                answerability.H3_BASE_INSTRUCTIONS.encode("utf-8")
            ).hexdigest(),
            "ec285d112e4b2a11ff3ae194ab6db79aeb8b5de32347918dc02e3543f3c30ea4",
        )

    def test_completion_invocation_binds_prompt_schema_model_parameters_and_payload(self):
        answerability = self._answerability()
        captured = []

        def complete(request):
            captured.append(request)
            return supported_decision()

        verifier = answerability.StructuredAnswerabilityVerifier(
            complete=complete,
            model_id="local-fixture",
            parameters={"temperature": 0},
        )
        result = progressive.progressive_access_knowledge(
            "What is the current replacement record?",
            enabled=True,
            planner=completion_flip_planner(),
            host=DirectHost(),
            query_id="query-bound-completion",
            answerability_verifier=verifier,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(captured), 1)
        request = captured[0]
        self.assertEqual(request.base_instructions, answerability.H3_BASE_INSTRUCTIONS)
        self.assertEqual(request.model_id, "local-fixture")
        self.assertEqual(request.parameters, {"temperature": 0})
        self.assertEqual(request.payload["contract"], answerability.H3_CONTRACT)
        self.assertEqual(
            result["answerability"]["completion_request_sha256"],
            request.request_sha256,
        )
        self.assertRegex(request.output_schema_sha256, r"^[0-9a-f]{64}$")

    def test_production_verifier_rejects_a_remote_transport_mode(self):
        answerability = self._answerability()
        with self.assertRaisesRegex(ValueError, "local_only"):
            answerability.StructuredAnswerabilityVerifier(
                complete=lambda request: supported_decision(),
                model_id="remote-model",
                transport_mode="remote",
            )

    def test_nested_parameters_are_frozen_at_verifier_construction(self):
        answerability = self._answerability()
        parameters = {"sampling": {"temperature": 0}}
        captured = []
        verifier = answerability.StructuredAnswerabilityVerifier(
            complete=lambda request: captured.append(request) or supported_decision(),
            model_id="local-fixture",
            parameters=parameters,
        )
        original_hash = verifier.parameters_sha256
        parameters["sampling"]["temperature"] = 1
        verifier.parameters["sampling"]["temperature"] = 2

        result = progressive.progressive_access_knowledge(
            "What is the current replacement record?",
            enabled=True,
            planner=completion_flip_planner(),
            host=DirectHost(),
            query_id="query-frozen-parameters",
            answerability_verifier=verifier,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(captured[0].parameters, {"sampling": {"temperature": 0}})
        self.assertEqual(result["answerability"]["parameters_sha256"], original_hash)

    def test_completion_deadline_fails_closed_without_a_second_call(self):
        started = threading.Event()
        release = threading.Event()
        calls = []

        def blocked(payload):
            calls.append(payload)
            started.set()
            release.wait(1.0)
            return supported_decision()

        try:
            result = self._run_direct(
                blocked,
                verifier_options={"completion_timeout_seconds": 0.01},
            )
        finally:
            release.set()

        self.assertTrue(started.is_set())
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["stop_reason"], "tool_failure")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["answerability"]["failure_type"], "verifier_timeout")

    def test_supported_direct_evidence_is_released_at_fixed_recall_first_policy(self):
        calls = []

        def complete(payload):
            calls.append(payload)
            return supported_decision()

        result = self._run_direct(complete)

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["stop_reason"], "sufficient_evidence")
        self.assertEqual([row["candidate_id"] for row in result["evidence"]], ["target"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["answerability"]["verifier_calls"], 1)
        self.assertTrue(result["answerability"]["triggered"])
        self.assertTrue(result["answerability"]["accepted"])
        self.assertEqual(result["answerability"]["threshold"], 0.35)
        self.assertEqual(result["answerability"]["structural_status"], "supported")

    def test_unsupported_and_underspecified_decisions_refuse_without_hits(self):
        for decision in (unsupported_decision(), unsupported_decision(underspecified=True)):
            with self.subTest(reason=decision["reason_code"]):
                result = self._run_direct(lambda payload, value=decision: value)

                self.assertEqual(result["status"], "no_answer")
                self.assertEqual(result["stop_reason"], "no_answer_calibrated")
                self.assertEqual(result["evidence"], [])
                self.assertFalse(result["answerability"]["accepted"])
                self.assertEqual(result["answerability"]["verifier_calls"], 1)

    def test_invalid_json_and_exception_each_fail_closed_after_one_call(self):
        def explode(payload):
            raise RuntimeError("/private/secret must not escape")

        for complete, failure in (
            (lambda payload: "not-json", "verifier_protocol_error"),
            (explode, "verifier_exception"),
        ):
            with self.subTest(failure=failure):
                result = self._run_direct(complete)

                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["stop_reason"], "tool_failure")
                self.assertEqual(result["evidence"], [])
                self.assertEqual(result["answerability"]["failure_type"], failure)
                self.assertEqual(result["answerability"]["verifier_calls"], 1)
                self.assertNotIn("private", json.dumps(result))

    def test_illegal_or_invisible_evidence_reference_fails_closed(self):
        result = self._run_direct(lambda payload: supported_decision("N99"))

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["stop_reason"], "tool_failure")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(
            result["answerability"]["failure_type"], "verifier_protocol_error"
        )

    def test_remote_payload_uses_an_exact_safe_allowlist_and_commitments(self):
        captured = []
        verifier = self._verifier(lambda payload: captured.append(payload) or supported_decision())
        result = progressive.progressive_access_knowledge(
            "What does /Users/example/private/record.md currently name?",
            enabled=True,
            planner=completion_flip_planner(),
            host=DirectHost(body="Record B; source /synthetic/private/secret.md"),
            query_id="query-/private/identifier",
            language="en",
            allowed_scopes=("private-workspace",),
            answerability_verifier=verifier,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(captured), 1)
        payload = captured[0]
        self.assertEqual(
            set(payload), {"budget", "contract", "dossier", "evidence_trust"}
        )
        self.assertEqual(
            set(payload["dossier"]),
            {
                "schema_version",
                "semantic_request",
                "host_governance",
                "loop_state",
                "evidence_nodes",
                "evidence_edges",
                "evidence_paths",
            },
        )
        rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        for forbidden in (
            "/Users/example",
            "/synthetic/private",
            "work_contexts/private",
            "private-workspace",
            "query-/private",
            "section:2",
            "auth:",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertRegex(
            payload["dossier"]["evidence_nodes"][0][
                "authority_commitment_sha256"
            ],
            r"^[0-9a-f]{64}$",
        )
        forbidden_keys = {
            "path",
            "source_revision",
            "revision",
            "locator",
            "authorization_handle",
            "candidate_id",
            "evidence_group_id",
            "planner_reasoning",
            "reasoning",
            "gold",
            "qrels",
            "scorer",
            "required_groups",
        }

        def all_keys(value):
            if isinstance(value, dict):
                return set(value).union(*(all_keys(item) for item in value.values()))
            if isinstance(value, list):
                return set().union(*(all_keys(item) for item in value)) if value else set()
            return set()

        self.assertFalse(forbidden_keys & all_keys(payload))

    def test_ordered_two_hop_support_preserves_edges_and_complete_path(self):
        answerability = self._answerability()
        captured = []

        def complete(payload):
            captured.append(payload)
            paths = payload["dossier"]["evidence_paths"]
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0]["ordered_node_refs"], ["N1", "N2", "N3"])
            self.assertEqual(paths[0]["ordered_edge_refs"], ["E1", "E2"])
            self.assertTrue(paths[0]["complete"])
            return supported_decision("P1")

        verifier = self._verifier(complete)
        planner = ScriptedPlanner(
            [
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("ordered terminus",),
                    0.2,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:hop-1",
                            relation="ordered_relation",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("ordered terminus",),
                    0.5,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:hop-2",
                            relation="ordered_relation",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "complete",
                    (),
                    0.95,
                    (),
                    final_evidence_ids=("target",),
                    stop_reason="sufficient_evidence",
                ),
            ]
        )

        result = progressive.progressive_access_knowledge(
            "Which entity is the ordered two-hop terminus?",
            enabled=True,
            planner=planner,
            host=ChainedRelationHost(answerability),
            answerability_verifier=verifier,
            query_id="query-two-hop",
            language="mixed",
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(captured), 1)

        malformed_order = json.loads(json.dumps(captured[0]))
        malformed_order["dossier"]["evidence_edges"][0]["order"] = True
        with self.assertRaises(answerability.DossierValidationError):
            answerability.validate_answerability_payload(malformed_order)

        non_adjacent = json.loads(json.dumps(captured[0]))
        non_adjacent["dossier"]["evidence_paths"][0]["ordered_node_refs"] = [
            "N1",
            "N3",
            "N2",
        ]
        with self.assertRaises(answerability.DossierValidationError):
            answerability.validate_answerability_payload(non_adjacent)

    def test_relation_support_without_a_path_reference_is_rejected(self):
        answerability = self._answerability()
        verifier = self._verifier(lambda payload: supported_decision("N3"))
        planner = ScriptedPlanner(
            [
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("ordered terminus",),
                    0.2,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:hop-1",
                            relation="ordered_relation",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("ordered terminus",),
                    0.5,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:hop-2",
                            relation="ordered_relation",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "complete",
                    (),
                    0.95,
                    (),
                    final_evidence_ids=("target",),
                    stop_reason="sufficient_evidence",
                ),
            ]
        )

        result = progressive.progressive_access_knowledge(
            "Which entity is the ordered two-hop terminus?",
            enabled=True,
            planner=planner,
            host=ChainedRelationHost(answerability),
            answerability_verifier=verifier,
            query_id="query-two-hop-no-path",
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["stop_reason"], "tool_failure")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(
            result["answerability"]["failure_type"], "verifier_protocol_error"
        )

    def test_relation_support_cannot_borrow_an_unrelated_path_citation(self):
        answerability = self._answerability()
        decision = supported_decision("P1")
        decision["facet_assessments"].append(
            {
                "facet": "relation terminus",
                "assessment": "supported",
                "evidence_refs": ["N3"],
            }
        )
        with self.assertRaises(answerability.AnswerabilityProtocolError):
            answerability.parse_answerability_decision(
                decision,
                visible_refs={"N1", "N2", "N3", "E1", "E2", "P1"},
                relation_path_required=True,
            )

    def test_malformed_authority_value_fails_closed_before_completion(self):
        calls = []

        class MalformedAuthorityHost:
            def execute(self, action, request, allowance):
                return progressive.ToolResult(
                    status="ok",
                    candidates=(
                        progressive.CandidateEvidence(
                            candidate_id="target",
                            evidence_group_id="entity:target",
                            summary="bad authority",
                            body="Record B",
                            authority=progressive.AuthorityReceipt(
                                path="work_contexts/example.md",
                                source_revision=Path("not-a-revision"),
                                source_sha256="b" * 64,
                                locator="section:1",
                                verified=True,
                            ),
                        ),
                    ),
                )

        result = progressive.progressive_access_knowledge(
            "What is the current replacement record?",
            enabled=True,
            planner=completion_flip_planner(),
            host=MalformedAuthorityHost(),
            query_id="query-malformed-authority",
            answerability_verifier=self._verifier(
                lambda payload: calls.append(payload) or supported_decision()
            ),
        )

        self.assertEqual(calls, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["stop_reason"], "authority_reopen_failed")
        self.assertEqual(result["evidence"], [])

    def test_relation_authority_commitment_mismatch_fails_before_completion(self):
        answerability = self._answerability()
        completion_calls = []
        verifier = self._verifier(
            lambda payload: completion_calls.append(payload) or supported_decision("P1")
        )
        planner = ScriptedPlanner(
            [
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("ordered terminus",),
                    0.2,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:hop-1",
                            relation="ordered_relation",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("ordered terminus",),
                    0.5,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:hop-2",
                            relation="ordered_relation",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "complete",
                    (),
                    0.95,
                    (),
                    final_evidence_ids=("target",),
                    stop_reason="sufficient_evidence",
                ),
            ]
        )

        result = progressive.progressive_access_knowledge(
            "Which entity is the ordered two-hop terminus?",
            enabled=True,
            planner=planner,
            host=ChainedRelationHost(answerability, bad_commitment=True),
            answerability_verifier=verifier,
            query_id="query-bad-commitment",
        )

        self.assertEqual(completion_calls, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["answerability"]["verifier_calls"], 0)
        self.assertEqual(
            result["answerability"]["failure_type"], "dossier_validation_error"
        )

    def test_unbound_advisory_follow_relation_cannot_be_accepted_by_h3(self):
        completion_calls = []
        verifier = self._verifier(
            lambda payload: completion_calls.append(payload) or supported_decision()
        )
        planner = ScriptedPlanner(
            [
                progressive.PlannerDecision(
                    "missing_evidence",
                    ("relation target",),
                    0.3,
                    (
                        progressive.RetrievalAction(
                            "follow_relation",
                            "relation",
                            authorization_handle="auth:advisory",
                            relation="related_to",
                        ),
                    ),
                ),
                progressive.PlannerDecision(
                    "complete",
                    (),
                    0.95,
                    (),
                    final_evidence_ids=("target",),
                    stop_reason="sufficient_evidence",
                ),
            ]
        )

        result = progressive.progressive_access_knowledge(
            "Which record is related to the seed?",
            enabled=True,
            planner=planner,
            host=UnboundRelationHost(),
            query_id="query-unbound-advisory-relation",
            answerability_verifier=verifier,
        )

        self.assertEqual(completion_calls, [])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["stop_reason"], "authority_reopen_failed")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["answerability"]["verifier_calls"], 0)
        self.assertEqual(
            result["answerability"]["failure_type"], "dossier_validation_error"
        )

    def test_untriggered_terminal_path_preserves_result_and_makes_no_verifier_call(self):
        calls = []
        verifier = self._verifier(lambda payload: calls.append(payload) or supported_decision())

        def immediate_planner():
            return ScriptedPlanner(
                [
                    progressive.PlannerDecision(
                        "complete",
                        (),
                        0.95,
                        (),
                        final_evidence_ids=("target",),
                        stop_reason="sufficient_evidence",
                    )
                ]
            )

        with mock.patch.object(progressive.time, "perf_counter", return_value=0.0):
            baseline = progressive.progressive_access_knowledge(
                "What is the current replacement record?",
                enabled=True,
                planner=immediate_planner(),
                host=DirectHost(),
                query_id="query-untriggered",
            )
            candidate = progressive.progressive_access_knowledge(
                "What is the current replacement record?",
                enabled=True,
                planner=immediate_planner(),
                host=DirectHost(),
                query_id="query-untriggered",
                answerability_verifier=verifier,
            )

        audit = candidate.pop("answerability")
        self.assertEqual(candidate, baseline)
        self.assertFalse(audit["triggered"])
        self.assertEqual(audit["verifier_calls"], 0)
        self.assertEqual(calls, [])

    def test_verifier_does_not_change_retrieval_budget_or_run_more_than_once(self):
        with mock.patch.object(progressive.time, "perf_counter", return_value=0.0):
            baseline = progressive.progressive_access_knowledge(
                "What is the current replacement record?",
                enabled=True,
                planner=completion_flip_planner(),
                host=DirectHost(),
                query_id="query-budget",
            )
            candidate = progressive.progressive_access_knowledge(
                "What is the current replacement record?",
                enabled=True,
                planner=completion_flip_planner(),
                host=DirectHost(),
                query_id="query-budget",
                answerability_verifier=self._verifier(
                    lambda payload: supported_decision()
                ),
            )

        self.assertEqual(candidate["budget"], baseline["budget"])
        self.assertEqual(candidate["trace"], baseline["trace"])
        self.assertLessEqual(candidate["answerability"]["verifier_calls"], 1)

    def test_unverified_final_candidate_still_fails_before_answerability_release(self):
        calls = []

        class UnverifiedHost:
            def execute(self, action, request, allowance):
                candidate = verified_candidate()
                return progressive.ToolResult(
                    status="ok",
                    candidates=(
                        progressive.CandidateEvidence(
                            candidate_id=candidate.candidate_id,
                            evidence_group_id=candidate.evidence_group_id,
                            summary=candidate.summary,
                            body=candidate.body,
                            authority=progressive.AuthorityReceipt(
                                path=candidate.authority.path,
                                source_revision=candidate.authority.source_revision,
                                source_sha256=candidate.authority.source_sha256,
                                locator=candidate.authority.locator,
                                verified=False,
                            ),
                        ),
                    ),
                )

        result = progressive.progressive_access_knowledge(
            "What is the current replacement record?",
            enabled=True,
            planner=completion_flip_planner(),
            host=UnverifiedHost(),
            query_id="query-unverified",
            answerability_verifier=self._verifier(
                lambda payload: calls.append(payload) or supported_decision()
            ),
        )

        self.assertEqual(result["stop_reason"], "authority_reopen_failed")
        self.assertEqual(result["evidence"], [])
        self.assertEqual(calls, [])
        self.assertEqual(result["answerability"]["verifier_calls"], 0)

    def test_decision_schema_and_runtime_validation_are_strict(self):
        answerability = self._answerability()
        schema_path = ROOT / "schemas" / "progressive_answerability_v1.schema.json"
        self.assertTrue(schema_path.is_file())
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertFalse(
            schema["properties"]["facet_assessments"]["items"][
                "additionalProperties"
            ]
        )

        valid = supported_decision()
        parsed = answerability.parse_answerability_decision(
            valid, visible_refs={"N1"}, relation_path_required=False
        )
        self.assertEqual(parsed["structural_status"], "supported")
        for mutation in (
            {**valid, "extra": "forbidden"},
            {**valid, "p_answerable": True},
            {**valid, "facet_assessments": []},
        ):
            with self.subTest(mutation=mutation):
                with self.assertRaises(answerability.AnswerabilityProtocolError):
                    answerability.parse_answerability_decision(
                        mutation,
                        visible_refs={"N1"},
                        relation_path_required=False,
                    )


if __name__ == "__main__":
    unittest.main()
