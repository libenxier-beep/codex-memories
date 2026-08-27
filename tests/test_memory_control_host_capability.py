from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from contextlib import redirect_stderr
from io import StringIO
import json
import subprocess
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))

import memory_control_plane  # noqa: E402
from memory_control_plane import MemoryControlPlane, ValidatorSpec  # noqa: E402
from memory_control_plane.model import canonical_json, digest_object  # noqa: E402
from memory_control_plane.projection import MemoryProjection  # noqa: E402
from memory_control_plane.recall_policy import RecallPolicy  # noqa: E402
import memory_control  # noqa: E402


NAMESPACE = "codex-memory-control-v1"


class MemoryControlHostCapabilityTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()

    def _cli(self, root: Path, *arguments: str) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "memory_control.py"),
                "--root",
                str(root),
                *arguments,
            ],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        envelope = json.loads(completed.stdout)
        self.assertEqual(0, completed.returncode, (envelope, completed.stderr))
        self.assertTrue(envelope["ok"])
        return envelope["result"]

    def _host_key(self, root: Path) -> tuple[Path, Path]:
        private_key = root / "host-key"
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "host-test",
                "-f",
                str(private_key),
            ],
            check=True,
        )
        public_fields = private_key.with_suffix(".pub").read_text(encoding="utf-8").split()
        allowed_signers = root / "allowed-signers"
        allowed_signers.write_text(
            'host@example.invalid namespaces="{}" {} {}\n'.format(
                NAMESPACE, public_fields[0], public_fields[1]
            ),
            encoding="utf-8",
        )
        return private_key, allowed_signers

    def _request(self) -> dict[str, object]:
        return {
            "phase": "authorize",
            "candidate_set_digest": "1" * 64,
            "approved_candidate_ids": ["cand_" + "2" * 64],
            "except_ids": [],
            "actor_claim": "user",
            "current_turn_ref": "turn:host-authorized",
            "mode": "approve_ids",
            "snapshots": [
                {
                    "proposal_id": "cand_" + "2" * 64,
                    "candidate_hash": "2" * 64,
                    "repository": {"repository_id": "memory-fixture"},
                    "source_revision": "fixture:v1",
                    "operation": "update",
                    "destination": "core/rule.md",
                    "target_precondition": {"state": "present", "sha256": "3" * 64},
                }
            ],
        }

    def _signed_capability(self, private_key: Path, statement: dict[str, object]) -> dict[str, object]:
        message = private_key.parent / "capability.json"
        message.write_bytes(canonical_json(statement))
        subprocess.run(
            [
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(private_key),
                "-n",
                NAMESPACE,
                str(message),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signature = message.with_suffix(".json.sig").read_text(encoding="ascii")
        return {"schema_version": 1, "statement": statement, "signature": signature}

    def test_real_ssh_signature_verifies_an_exact_authorization_request(self) -> None:
        self.assertTrue(
            hasattr(memory_control_plane, "SshHostAuthorizationVerifier"),
            "the production package must expose a real host verifier",
        )
        self.assertTrue(
            hasattr(memory_control_plane, "build_host_authorization_statement"),
            "the host needs a deterministic unsigned statement builder",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_key, allowed_signers = self._host_key(root)
            request = self._request()
            statement = memory_control_plane.build_host_authorization_statement(
                request,
                signer_identity="host@example.invalid",
                nonce="4" * 64,
                issued_at="2026-08-20T00:00:00Z",
                expires_at="2026-08-20T00:10:00Z",
                authorized_phases=("authorize", "apply"),
            )
            capability = self._signed_capability(private_key, statement)
            verifier = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=allowed_signers,
                allowed_signers_sha256=hashlib.sha256(allowed_signers.read_bytes()).hexdigest(),
                now=lambda: datetime(2026, 8, 20, 0, 5, tzinfo=timezone.utc),
            )

            self.assertEqual(
                "cap_"
                + digest_object(
                    {
                        "schema_version": 1,
                        "statement_capability_id": statement["capability_id"],
                        "allowed_signers_sha256": hashlib.sha256(
                            allowed_signers.read_bytes()
                        ).hexdigest(),
                        "signer_identity": "host@example.invalid",
                        "namespace": NAMESPACE,
                    }
                ),
                verifier(capability, request),
            )

    def test_cli_exposes_request_and_requires_external_capability_for_mutation(self) -> None:
        common = [
            "--host-allowed-signers",
            "/host/allowed_signers",
            "--host-allowed-signers-sha256",
            "5" * 64,
        ]
        try:
            request_args = memory_control.parser().parse_args(
                [
                    "authorization-request",
                    "--set-digest",
                    "1" * 64,
                    "--evidence",
                    "approval.json",
                ]
            )
            authorize_args = memory_control.parser().parse_args(
                common
                + [
                    "authorize",
                    "--set-digest",
                    "1" * 64,
                    "--evidence",
                    "approval.json",
                    "--host-capability",
                    "/host/capability.json",
                ]
            )
        except SystemExit:
            self.fail("the production CLI host-capability seam is missing")

        self.assertEqual("authorization-request", request_args.command)
        self.assertEqual(Path("/host/capability.json"), authorize_args.host_capability)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            memory_control.parser().parse_args(
                common
                + [
                    "authorize",
                    "--set-digest",
                    "1" * 64,
                    "--evidence",
                    "approval.json",
                ]
            )

    def test_tamper_wrong_set_phase_expiry_and_trust_anchor_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_key, allowed_signers = self._host_key(root)
            request = self._request()
            statement = memory_control_plane.build_host_authorization_statement(
                request,
                signer_identity="host@example.invalid",
                nonce="6" * 64,
                issued_at="2026-08-20T00:00:00Z",
                expires_at="2026-08-20T00:10:00Z",
                authorized_phases=("authorize", "apply"),
            )
            capability = self._signed_capability(private_key, statement)
            allowed_digest = hashlib.sha256(allowed_signers.read_bytes()).hexdigest()
            verifier = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=allowed_signers,
                allowed_signers_sha256=allowed_digest,
                now=lambda: datetime(2026, 8, 20, 0, 5, tzinfo=timezone.utc),
            )

            wrong_set = dict(request)
            wrong_set["candidate_set_digest"] = "9" * 64
            with self.assertRaisesRegex(ValueError, "does not bind"):
                verifier(capability, wrong_set)
            wrong_action = json.loads(json.dumps(request))
            wrong_action["snapshots"][0]["operation"] = "add"
            with self.assertRaisesRegex(ValueError, "does not bind"):
                verifier(capability, wrong_action)
            wrong_proposal = json.loads(json.dumps(request))
            wrong_proposal["approved_candidate_ids"] = ["cand_" + "9" * 64]
            with self.assertRaisesRegex(ValueError, "does not bind"):
                verifier(capability, wrong_proposal)
            wrong_phase = {**request, "phase": "recover", "approval_id": "appr_" + "8" * 64}
            with self.assertRaisesRegex(ValueError, "does not authorize this phase"):
                verifier(capability, wrong_phase)
            tampered = json.loads(json.dumps(capability))
            tampered["statement"]["authorization_request"]["snapshots"][0]["operation"] = "add"
            with self.assertRaises(ValueError):
                verifier(tampered, request)
            expired = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=allowed_signers,
                allowed_signers_sha256=allowed_digest,
                now=lambda: datetime(2026, 8, 20, 0, 10, tzinfo=timezone.utc),
            )
            with self.assertRaisesRegex(ValueError, "validity window"):
                expired(capability, request)
            replaced_anchor = root / "replaced-allowed-signers"
            replaced_anchor.write_bytes(allowed_signers.read_bytes() + b"\n")
            wrong_anchor = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=replaced_anchor,
                allowed_signers_sha256=allowed_digest,
                now=lambda: datetime(2026, 8, 20, 0, 5, tzinfo=timezone.utc),
            )
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                wrong_anchor(capability, request)

    def test_verified_capability_id_binds_the_host_trust_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host_a = root / "host-a"
            host_b = root / "host-b"
            host_a.mkdir()
            host_b.mkdir()
            key_a, allowed_a = self._host_key(host_a)
            key_b, allowed_b = self._host_key(host_b)
            request = self._request()
            statement = memory_control_plane.build_host_authorization_statement(
                request,
                signer_identity="host@example.invalid",
                nonce="a" * 64,
                issued_at="2026-08-20T00:00:00Z",
                expires_at="2026-08-20T00:10:00Z",
                authorized_phases=("authorize", "apply"),
            )
            capability_a = self._signed_capability(key_a, statement)
            capability_b = self._signed_capability(key_b, statement)
            verifier_a = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=allowed_a,
                allowed_signers_sha256=hashlib.sha256(allowed_a.read_bytes()).hexdigest(),
                now=lambda: datetime(2026, 8, 20, 0, 5, tzinfo=timezone.utc),
            )
            verifier_b = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=allowed_b,
                allowed_signers_sha256=hashlib.sha256(allowed_b.read_bytes()).hexdigest(),
                now=lambda: datetime(2026, 8, 20, 0, 5, tzinfo=timezone.utc),
            )

            self.assertNotEqual(
                verifier_a(capability_a, request),
                verifier_b(capability_b, request),
                "an approval minted under one trust anchor must not apply under another",
            )

    def test_cli_consumes_but_never_mints_the_external_host_capability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._git(root, "init", "-b", "main")
            self._git(root, "config", "user.name", "CLI Host Fixture")
            self._git(root, "config", "user.email", "cli-host@example.invalid")
            (root / "core").mkdir()
            (root / "core" / "rule.md").write_text("old rule\n", encoding="utf-8")
            (root / "evidence").mkdir()
            (root / "evidence" / "source.txt").write_text("source evidence\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-m", "baseline")
            private_key, allowed_signers = self._host_key(root)
            allowed_digest = hashlib.sha256(allowed_signers.read_bytes()).hexdigest()
            candidate_path = root / "candidate.json"
            gates_path = root / "gates.json"
            assessment_path = root / "assessment.json"
            evidence_path = root / "approval-evidence.json"
            candidate_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "normalization_version": 1,
                        "operation": "no_op",
                        "destination": "core/rule.md",
                        "draft_write": "old rule\n",
                        "scope": "global",
                        "applies_to": "all",
                        "owner": "cli-host-fixture",
                        "source_refs": [
                            {
                                "kind": "repository_file",
                                "ref": "evidence/source.txt",
                                "sha256": hashlib.sha256(b"source evidence\n").hexdigest(),
                            }
                        ],
                        "source_revision": "fixture:v1",
                        "valid_from": None,
                        "valid_to": None,
                        "sensitivity": "work",
                    }
                ),
                encoding="utf-8",
            )
            gates_path.write_text(
                json.dumps(
                    {
                        name: "pass"
                        for name in (
                            "prompt_injection",
                            "executable_payload",
                            "provenance",
                            "scope",
                            "stability",
                            "high_stakes",
                            "authority_conflict",
                        )
                    }
                ),
                encoding="utf-8",
            )
            assessment_path.write_text(
                json.dumps(
                    {
                        "scores": {
                            "recurrence": 2,
                            "transferability": 2,
                            "stability": 2,
                            "impact": 2,
                            "contamination_risk": 0,
                        },
                        "deduplication": "novel",
                        "conflict": "none",
                    }
                ),
                encoding="utf-8",
            )
            proposal = self._cli(
                root,
                "prepare",
                "--candidate",
                str(candidate_path),
                "--gates",
                str(gates_path),
            )
            self._cli(
                root,
                "assess",
                "--proposal",
                str(proposal["proposal_id"]),
                "--assessment",
                str(assessment_path),
            )
            evidence = {
                "mode": "approve_ids",
                "candidate_ids": [proposal["proposal_id"]],
                "actor_claim": "user",
                "current_turn_ref": "turn:cli-host-e2e",
            }
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            request = self._cli(
                root,
                "authorization-request",
                "--set-digest",
                str(proposal["candidate_set_digest"]),
                "--evidence",
                str(evidence_path),
            )
            issued = datetime.now(timezone.utc)
            expires = issued + timedelta(minutes=10)
            statement = memory_control_plane.build_host_authorization_statement(
                request,
                signer_identity="host@example.invalid",
                nonce="8" * 64,
                issued_at=issued.isoformat().replace("+00:00", "Z"),
                expires_at=expires.isoformat().replace("+00:00", "Z"),
                authorized_phases=("authorize", "apply"),
            )
            capability_path = root / "host-capability.json"
            capability_path.write_text(
                json.dumps(self._signed_capability(private_key, statement)),
                encoding="utf-8",
            )
            host_options = (
                "--host-allowed-signers",
                str(allowed_signers),
                "--host-allowed-signers-sha256",
                allowed_digest,
            )
            approval = self._cli(
                root,
                *host_options,
                "authorize",
                "--set-digest",
                str(proposal["candidate_set_digest"]),
                "--evidence",
                str(evidence_path),
                "--host-capability",
                str(capability_path),
            )
            receipt = self._cli(
                root,
                *host_options,
                "apply-workspace",
                "--proposal",
                str(proposal["proposal_id"]),
                "--approval",
                str(approval["approval_id"]),
                "--host-capability",
                str(capability_path),
            )

            self.assertEqual("workspace_applied", receipt["status"])
            self.assertEqual("no_op", receipt["operation"])

    def test_signed_capability_closes_apply_commit_rebuild_and_canonical_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self._git(root, "init", "-b", "main")
            self._git(root, "config", "user.name", "Host Capability Fixture")
            self._git(root, "config", "user.email", "host-capability@example.invalid")
            (root / "core").mkdir()
            (root / "core" / "base.md").write_text("# Base\n", encoding="utf-8")
            (root / "learnings").mkdir()
            (root / "learnings" / ".gitkeep").write_text("", encoding="utf-8")
            (root / "evidence").mkdir()
            (root / "evidence" / "source.txt").write_text("source evidence\n", encoding="utf-8")
            (root / "validate.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
            self._git(root, "add", ".")
            self._git(root, "commit", "-m", "baseline")
            private_key, allowed_signers = self._host_key(root)
            allowed_digest = hashlib.sha256(allowed_signers.read_bytes()).hexdigest()
            verifier = memory_control_plane.SshHostAuthorizationVerifier(
                allowed_signers_path=allowed_signers,
                allowed_signers_sha256=allowed_digest,
                now=lambda: datetime(2026, 8, 20, 0, 5, tzinfo=timezone.utc),
            )
            plane = MemoryControlPlane(
                repository=root,
                control_root=root / "control_plane",
                repository_id="host-capability-fixture",
                policy_version="test-v1",
                allowed_subtrees=("core", "platform", "learnings"),
                validators=(
                    ValidatorSpec(
                        name="fixture",
                        argv=(sys.executable, "validate.py"),
                        timeout_seconds=5,
                    ),
                ),
                host_authorization_verifier=verifier,
            )
            draft = (
                "---\n"
                "id: host-approved-rule\n"
                "scope: learning\n"
                "applies_to: all\n"
                "status: active\n"
                "authorization_state: user_approved\n"
                "provenance_trust: source_bound_candidate\n"
                "privacy_class: private_local\n"
                "---\n\n"
                "# Host approved rule\n\n"
                "Use the signed canonical reopen marker.\n"
            )
            candidate = {
                "schema_version": 1,
                "normalization_version": 1,
                "operation": "add",
                "destination": "learnings/host-approved-rule.md",
                "draft_write": draft,
                "scope": "learning",
                "applies_to": "all",
                "owner": "host-capability-fixture",
                "source_refs": [
                    {
                        "kind": "repository_file",
                        "ref": "evidence/source.txt",
                        "sha256": hashlib.sha256(b"source evidence\n").hexdigest(),
                    }
                ],
                "source_revision": "fixture:v1",
                "valid_from": None,
                "valid_to": None,
                "sensitivity": "work",
            }
            gates = {
                name: "pass"
                for name in (
                    "prompt_injection",
                    "executable_payload",
                    "provenance",
                    "scope",
                    "stability",
                    "high_stakes",
                    "authority_conflict",
                )
            }
            proposal = plane.prepare(candidate, gates)
            self.assertEqual("quarantined", proposal["disposition"], proposal)
            plane.assess(
                str(proposal["proposal_id"]),
                {
                    "scores": {
                        "recurrence": 2,
                        "transferability": 2,
                        "stability": 2,
                        "impact": 2,
                        "contamination_risk": 0,
                    },
                    "deduplication": "novel",
                    "conflict": "none",
                },
            )
            evidence = {
                "mode": "approve_ids",
                "candidate_ids": [str(proposal["proposal_id"])],
                "actor_claim": "user",
                "current_turn_ref": "turn:host-capability-e2e",
            }
            request = plane.authorization_request(
                str(proposal["candidate_set_digest"]), evidence
            )
            statement = memory_control_plane.build_host_authorization_statement(
                request,
                signer_identity="host@example.invalid",
                nonce="7" * 64,
                issued_at="2026-08-20T00:00:00Z",
                expires_at="2026-08-20T00:10:00Z",
                authorized_phases=("authorize", "apply"),
            )
            capability = self._signed_capability(private_key, statement)
            approval = plane.authorize(
                str(proposal["candidate_set_digest"]),
                evidence,
                host_capability=capability,
            )
            replayed_approval = plane.authorize(
                str(proposal["candidate_set_digest"]),
                evidence,
                host_capability=capability,
            )
            receipt = plane.apply_workspace(
                str(proposal["proposal_id"]),
                str(approval["approval_id"]),
                host_capability=capability,
            )
            replayed_receipt = plane.apply_workspace(
                str(proposal["proposal_id"]),
                str(approval["approval_id"]),
                host_capability=capability,
            )

            self.assertEqual(approval["approval_id"], replayed_approval["approval_id"])
            self.assertEqual(receipt["receipt_id"], replayed_receipt["receipt_id"])
            self.assertTrue(approval["host_authenticated"])
            artifact_text = (
                root / "control_plane" / "approvals" / f'{approval["approval_id"]}.md'
            ).read_text(encoding="utf-8")
            self.assertNotIn("BEGIN SSH SIGNATURE", artifact_text)
            self.assertNotIn("PRIVATE KEY", artifact_text)
            self._git(root, "add", "learnings/host-approved-rule.md")
            self._git(root, "commit", "-m", "publish host authorized rule")
            policy = RecallPolicy.from_mapping(
                {
                    "schema_version": 1,
                    "scopes": ["learning"],
                    "applies_to": "all",
                    "as_of": "2026-08-20T00:05:00Z",
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
            projection = MemoryProjection(
                repository=root,
                index_path=root / ".runtime" / "authority.sqlite",
                authority_roots=("core", "platform", "learnings"),
                force_no_fts=True,
            )
            projection.build(context=policy)
            recalled = projection.recall("signed canonical reopen marker", context=policy)

            self.assertEqual("hit", recalled["status"])
            self.assertTrue(recalled["matches"][0]["canonical_reopened"])


if __name__ == "__main__":
    unittest.main()
