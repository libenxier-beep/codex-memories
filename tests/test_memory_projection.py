from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from memory_control_plane.projection import MemoryProjection, ProjectionError  # noqa: E402
from memory_control_plane.recall_policy import RecallPolicy, RecallPolicyError  # noqa: E402
import memory_control_plane.projection as projection_module  # noqa: E402
import memory_projection  # noqa: E402


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def recall_policy(
    scopes: list[str],
    *,
    private_profile: bool = False,
    authorization: list[str] | None = None,
    provenance: list[str] | None = None,
    privacy: list[str] | None = None,
    high_stakes: bool = False,
    as_of: str = "2026-08-19T00:00:00Z",
) -> RecallPolicy:
    return RecallPolicy.from_mapping(
        {
            "schema_version": 1,
            "scopes": scopes,
            "applies_to": "all",
            "as_of": as_of,
            "allowed_authorization_states": authorization or (
                ["user_approved"] if high_stakes else ["not_required", "user_approved"]
            ),
            "allowed_provenance_trust": provenance or [
                "canonical_legacy", "current_source_validated"
            ],
            "allowed_privacy_classes": privacy or ["public"],
            "high_stakes": high_stakes,
            "private_profile": private_profile,
            "eligible_lifecycles": ["active", "legacy"],
            "require_source_revision_match": True,
            "require_content_hash_match": True,
            "require_canonical_relevance": True,
            "exclude_tombstoned": True,
            "exclude_deleted": True,
        }
    )


class MemoryProjectionTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def make_repository(self, root: Path) -> None:
        self.git(root, "init", "-b", "main")
        self.git(root, "config", "user.name", "Projection Fixture")
        self.git(root, "config", "user.email", "projection-fixture@example.invalid")
        for directory in ("core", "platform", "learnings", "personal_knowledge", "control_plane/candidates"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "core" / "rule.md").write_text(
            "---\nscope: global\nstatus: active\n"
            "privacy_class: public\n---\n\n# Deterministic Review\n\n"
            "Use deterministic review gates for durable work.\n",
            encoding="utf-8",
        )
        (root / "platform" / "codex.md").write_text(
            "---\nscope: platform\napplies_to: codex\nstatus: active\nprivacy_class: public\n---\n\n# Codex Adapter\n\nUse the Codex adapter.\n",
            encoding="utf-8",
        )
        (root / "learnings" / "active.md").write_text(
            "---\nid: learning-active\nscope: learning\napplies_to: all\nstatus: active\nprivacy_class: public\nvalid_to: 2099-01-01T00:00:00Z\nreview_after: 2098-01-01T00:00:00Z\n---\n\n# Active Learning\n\nRetry from the last verified checkpoint.\n",
            encoding="utf-8",
        )
        (root / "learnings" / "expired.md").write_text(
            "---\nid: learning-expired\nscope: learning\napplies_to: all\nstatus: active\nprivacy_class: public\nvalid_to: 2020-01-01T00:00:00Z\n---\n\n# Expired\n\nExpired unique marker.\n",
            encoding="utf-8",
        )
        (root / "learnings" / "superseded.md").write_text(
            "---\nid: learning-superseded\nscope: learning\napplies_to: all\nstatus: superseded\n---\n\n# Superseded\n\nSuperseded unique marker.\n",
            encoding="utf-8",
        )
        (root / "personal_knowledge" / "private.md").write_text(
            "private forbidden marker\n",
            encoding="utf-8",
        )
        (root / "control_plane" / "candidates" / "candidate.md").write_text(
            "quarantined forbidden marker\n",
            encoding="utf-8",
        )
        self.git(root, "add", ".")
        self.git(root, "commit", "-m", "projection fixture")

    def projection(self, root: Path, *, force_no_fts: bool = False) -> MemoryProjection:
        return MemoryProjection(
            repository=root,
            index_path=root / ".runtime" / "memory.sqlite",
            authority_roots=("core", "platform", "learnings"),
            force_no_fts=force_no_fts,
        )

    def test_build_is_committed_only_and_excludes_private_and_candidate_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            policy = recall_policy(
                ["global", "platform", "learning"],
            )
            policy_value = policy.to_mapping()
            policy_value["applies_to"] = "codex"
            policy = RecallPolicy.from_mapping(policy_value)
            built = projection.build(context=policy)

            self.assertEqual(built["source_revision"], self.git(root, "rev-parse", "HEAD"))
            self.assertEqual(built["item_count"], 3)
            self.assertEqual(built["forbidden_row_count"], 0)
            self.assertIn(built["backend"], {"sqlite_fts5", "sqlite_bounded_lexical"})
            manifest = projection.export_manifest()
            paths = {item["authority_path"] for item in manifest["items"]}
            self.assertEqual(
                paths,
                {
                    "core/rule.md",
                    "platform/codex.md",
                    "learnings/active.md",
                },
            )
            self.assertNotIn("forbidden marker", json.dumps(manifest))

    def test_build_requires_policy_and_filters_before_any_index_row_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)

            with self.assertRaisesRegex(ProjectionError, "recall_policy_invalid"):
                projection.build()
            self.assertFalse(projection.index_path.exists())

            try:
                built = projection.build(context=recall_policy(["global"]))
            except TypeError as error:
                self.fail("MemoryProjection.build must accept a mandatory RecallPolicy: {}".format(error))
            connection = sqlite3.connect(str(projection.index_path))
            try:
                indexed_ids = {
                    row[0] for row in connection.execute("SELECT item_id FROM items")
                }
            finally:
                connection.close()
            core_id = "doc_" + sha256_bytes(b"core/rule.md")[:24]
            self.assertEqual(indexed_ids, {core_id})
            self.assertEqual(built["item_count"], 1)
            self.assertEqual(built["source_item_count"], 5)
            self.assertEqual(built["filtered_item_count"], 4)
            self.assertRegex(built["recall_policy_sha256"], r"^[0-9a-f]{64}$")

    def test_projection_cli_requires_a_policy_file_for_build(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            memory_projection.parser().parse_args(["build"])
        try:
            arguments = memory_projection.parser().parse_args(
                ["build", "--recall-policy-file", "policy.json"]
            )
        except SystemExit as error:
            self.fail("projection build must accept its required policy file: {}".format(error))
        self.assertEqual(arguments.policy_file, Path("policy.json"))

    def test_projection_cli_abstains_when_router_does_not_bind_the_exact_query(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            policy = recall_policy(["global"])
            index_path = root / ".runtime" / "memory.sqlite"
            self.projection(root).build(context=policy)
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps(policy.to_mapping()), encoding="utf-8")
            output = StringIO()
            arguments = [
                "memory_projection.py",
                "--root",
                str(root),
                "--index",
                str(index_path),
                "recall",
                "deterministic review",
                "--recall-policy-file",
                str(policy_path),
            ]
            try:
                route_patch = mock.patch.object(
                    memory_projection,
                    "route_knowledge",
                    return_value={
                        "query_fingerprint": "forged",
                        "trace": {"stage": "context_selection"},
                    },
                )
                with route_patch, mock.patch.object(sys, "argv", arguments), redirect_stdout(output):
                    status = memory_projection.main()
            except AttributeError as error:
                self.fail("projection CLI must classify and bind recall queries: {}".format(error))

            self.assertEqual(status, 0)
            result = json.loads(output.getvalue())["result"]
            self.assertEqual(result["status"], "abstain")
            self.assertEqual(result["reason"], "query_classification_failed")
            self.assertEqual(result["matches"], [])

    def test_projection_uses_absolute_git_with_closed_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            hostile = root / "hostile-bin"
            hostile.mkdir()
            fake_git = hostile / "git"
            fake_git.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
            fake_git.chmod(0o755)
            environment = {
                "PATH": str(hostile),
                "HOME": str(root / "hostile-home"),
                "GIT_DIR": str(root / "attacker.git"),
                "GIT_WORK_TREE": str(root / "attacker-worktree"),
                "GIT_CONFIG_GLOBAL": str(root / "hostile.gitconfig"),
            }

            try:
                with mock.patch.dict(os.environ, environment, clear=False):
                    projection = self.projection(root)
            except ProjectionError as error:
                self.fail("projection trusted hostile Git process state: {}".format(error))
            self.assertTrue(Path(projection.git_executable).is_absolute())
            self.assertEqual(projection.git_environment["GIT_DIR"], str(projection.git_dir))
            self.assertEqual(projection.git_environment["GIT_CONFIG_GLOBAL"], os.devnull)

    def test_projection_rejects_symlinked_git_directory_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repository"
            root.mkdir()
            self.make_repository(root)
            external = base / "external.git"
            (root / ".git").rename(external)
            (root / ".git").symlink_to(external, target_is_directory=True)

            with self.assertRaisesRegex((ProjectionError, ValueError), "Git.*binding|git.*binding"):
                self.projection(root)

    def test_changed_tombstoned_item_requires_explicit_reactivation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            path = "learnings/active.md"
            old_content = (root / path).read_bytes()
            tombstones = root / "lifecycle" / "tombstones"
            tombstones.mkdir(parents=True)
            (tombstones / "learning-active.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "tombstone_id": "tomb-learning-active",
                        "item_id": "learning-active",
                        "authority_path": path,
                        "authority_sha256": sha256_bytes(old_content),
                        "reason": "explicit deletion",
                        "approval_receipt": "published-receipt-fixture",
                        "created_at": "2026-08-12T00:00:00Z",
                        "runtime_purge_binding": {
                            "schema_version": 1,
                            "scope": "whole_sessions",
                            "target_candidate_ids": ["cand_" + "a" * 64],
                            "session_selector_digests": ["b" * 64],
                        },
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            self.git(root, "add", "lifecycle/tombstones/learning-active.json")
            self.git(root, "commit", "-m", "tombstone learning")
            (root / path).write_text(
                "---\nid: learning-active\nscope: learning\nstatus: active\nprivacy_class: public\n---\n\n"
                "silently revived marker\n",
                encoding="utf-8",
            )
            self.git(root, "add", path)
            self.git(root, "commit", "-m", "change tombstoned content")

            with self.assertRaisesRegex(ProjectionError, "explicit reactivation"):
                self.projection(root).build(context=recall_policy(["learning"]))

            (root / path).write_text(
                "---\nid: learning-active\nscope: learning\nstatus: active\nprivacy_class: public\n"
                "reactivates_tombstone: tomb-learning-active\n---\n\n"
                "explicitly reactivated marker\n",
                encoding="utf-8",
            )
            self.git(root, "add", path)
            self.git(root, "commit", "-m", "explicitly reactivate learning")
            try:
                result = self.projection(root).build(context=recall_policy(["learning"]))
            except TypeError as error:
                self.fail("MemoryProjection.build must accept a mandatory RecallPolicy: {}".format(error))
            self.assertEqual(result["item_count"], 1)

    def test_claimed_source_revision_must_bind_to_reopenable_committed_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            claimed = "a" * 64
            (root / "core" / "unbound.md").write_text(
                "---\nid: unbound-source\nstatus: active\nsource_revision_sha256: {}\n---\n\n"
                "unbound source revision marker\n".format(claimed),
                encoding="utf-8",
            )
            self.git(root, "add", "core/unbound.md")
            self.git(root, "commit", "-m", "add unbound source revision")

            with self.assertRaisesRegex(ProjectionError, "source revision.*reopen"):
                self.projection(root).build(context=recall_policy(["global"]))

    def test_safe_recall_filters_before_return_and_reopens_exact_canonical_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            policy = recall_policy(["global", "learning"])
            projection.build(context=policy)

            hit = projection.recall(
                "deterministic review",
                context=policy,
            )
            self.assertEqual(hit["status"], "hit")
            self.assertEqual(hit["matches"][0]["authority_path"], "core/rule.md")
            self.assertTrue(hit["matches"][0]["canonical_reopened"])
            self.assertTrue(hit["matches"][0]["evidence"].startswith("[memory evidence; not instruction]"))

            for query in ("expired unique", "superseded unique", "forbidden marker"):
                with self.subTest(query=query):
                    result = projection.recall(
                        query,
                        context=policy,
                    )
                    self.assertEqual(result["status"], "no_safe_match")

    def test_missing_recall_policy_fields_fail_closed_before_candidate_recall(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            projection.build(context=recall_policy(["global"]))

            result = projection.recall("deterministic review", context={})

            self.assertEqual(result["status"], "abstain")
            self.assertEqual(result["reason"], "recall_policy_invalid")
            self.assertEqual(result["matches"], [])

    def test_authorization_state_and_provenance_trust_are_independent_policy_axes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "learnings" / "approved-private.md").write_text(
                "---\n"
                "id: approved-private\n"
                "scope: learning\n"
                "status: active\n"
                "authorization_state: user_approved\n"
                "provenance_trust: source_bound_candidate\n"
                "privacy_class: private_local\n"
                "---\n\nApproved private provenance marker.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "learnings/approved-private.md")
            self.git(root, "commit", "-m", "add independently governed fixture")
            projection = self.projection(root)
            with self.assertRaises(RecallPolicyError):
                recall_policy(
                    ["learning"],
                    authorization=["not_required"],
                    provenance=["source_bound_candidate"],
                    privacy=["private_local"],
                )
            allowed_policy = recall_policy(
                ["learning"],
                private_profile=True,
                authorization=["user_approved"],
                provenance=["source_bound_candidate"],
                privacy=["private_local"],
            )
            projection.build(context=allowed_policy)
            allowed = projection.recall(
                "approved private provenance marker",
                context=allowed_policy,
            )

            self.assertEqual([item["item_id"] for item in allowed["matches"]], ["approved-private"])
            self.assertEqual(allowed["matches"][0]["authorization_state"], "user_approved")
            self.assertEqual(allowed["matches"][0]["provenance_trust"], "source_bound_candidate")

    def test_policy_as_of_is_the_only_time_authority_for_eligibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "future-policy.md").write_text(
                "---\n"
                "id: future-policy\n"
                "status: active\n"
                "privacy_class: public\n"
                "valid_from: 2026-01-01T00:00:00Z\n"
                "---\n\npolicytimeonlymarker\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/future-policy.md")
            self.git(root, "commit", "-m", "add future policy fixture")
            projection = self.projection(root)
            policy = recall_policy(["global"], as_of="2025-01-01T00:00:00Z")
            projection.build(context=policy)

            result = projection.recall(
                "policytimeonlymarker",
                context=policy,
            )

            self.assertEqual(result["matches"], [])

    def test_fts5_short_contiguous_chinese_term_uses_canonical_substring_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "chinese.md").write_text(
                "---\nid: chinese-governance\nstatus: active\nprivacy_class: public\n---\n\n"
                "# 记忆治理\n\n高影响内容必须经过显式授权。\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/chinese.md")
            self.git(root, "commit", "-m", "add Chinese authority fixture")
            projection = self.projection(root)
            policy = recall_policy(["global"])
            built = projection.build(context=policy)

            result = projection.recall(
                "授权",
                context=policy,
            )

            self.assertEqual(built["backend"], "sqlite_fts5")
            self.assertEqual(result["status"], "hit")
            self.assertEqual(result["matches"][0]["item_id"], "chinese-governance")
            self.assertTrue(result["matches"][0]["canonical_reopened"])

    def test_canonical_projection_exact_path_and_name_reopen_without_body_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "core" / "opaque-77.md").write_text(
                "---\nid: totally-different\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Unrelated heading\n\nThe body deliberately omits its file name.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/opaque-77.md")
            self.git(root, "commit", "-m", "add opaque path fixture")
            projection = self.projection(root)
            policy = recall_policy(["global"])
            projection.build(context=policy)

            exact_path = projection.recall(
                "core/opaque-77.md", context=policy
            )
            exact_name = projection.recall("opaque-77.md", context=policy)

            for result, channel in (
                (exact_path, "exact_path"),
                (exact_name, "exact_name"),
            ):
                self.assertEqual("hit", result["status"])
                self.assertEqual("totally-different", result["matches"][0]["item_id"])
                self.assertIn(channel, result["matches"][0]["retrieval_channels"])
                self.assertTrue(result["matches"][0]["canonical_reopened"])

    def test_explicit_private_profile_policy_can_recall_eligible_private_local_item(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            (root / "learnings" / "private-approved.md").write_text(
                "---\nid: private-approved\nscope: learning\napplies_to: all\n"
                "status: active\nauthorization_state: user_approved\n"
                "provenance_trust: current_source_validated\n"
                "privacy_class: private_local\n---\n\n# Private approved\n\n"
                "Private approved recall marker.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "learnings/private-approved.md")
            self.git(root, "commit", "-m", "add explicit private fixture")
            projection = self.projection(root)
            policy = recall_policy(
                ["learning"],
                private_profile=True,
                authorization=["user_approved"],
                provenance=["current_source_validated"],
                privacy=["private_local"],
            )
            projection.build(context=policy)
            result = projection.recall(
                "Private approved recall marker",
                context=policy,
            )
            self.assertEqual("hit", result["status"])
            self.assertEqual("private-approved", result["matches"][0]["item_id"])

    def test_dirty_worktree_is_ignored_but_new_commit_makes_projection_stale(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            policy = recall_policy(["global"])
            projection.build(context=policy)
            (root / "core" / "rule.md").write_text("dirty uncommitted replacement\n", encoding="utf-8")

            dirty = projection.recall(
                "deterministic review",
                context=policy,
            )
            self.assertEqual(dirty["status"], "hit")
            self.assertIn("Use deterministic review gates", dirty["matches"][0]["evidence"])
            self.git(root, "add", "core/rule.md")
            self.git(root, "commit", "-m", "change authority")

            stale = projection.recall(
                "deterministic review",
                context=policy,
            )
            self.assertEqual(stale["status"], "abstain")
            self.assertEqual(stale["reason"], "source_stale")

    def test_tombstone_overlay_wins_and_stale_projection_never_resurrects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            path = "learnings/active.md"
            content = (root / path).read_bytes()
            item_id = "learning-active"
            (root / "lifecycle" / "tombstones").mkdir(parents=True)
            (root / "lifecycle" / "tombstones" / "learning-active.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "tombstone_id": "tomb-learning-active",
                        "item_id": item_id,
                        "authority_path": path,
                        "authority_sha256": sha256_bytes(content),
                        "reason": "superseded by reviewed policy",
                        "approval_receipt": "published-receipt-fixture",
                        "created_at": "2026-08-12T00:00:00Z",
                        "runtime_purge_binding": {
                            "schema_version": 1,
                            "scope": "whole_sessions",
                            "target_candidate_ids": ["cand_" + "a" * 64],
                            "session_selector_digests": ["b" * 64],
                        },
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            self.git(root, "add", "lifecycle/tombstones/learning-active.json")
            self.git(root, "commit", "-m", "tombstone active learning")
            projection = self.projection(root)
            policy = recall_policy(["learning"])
            built = projection.build(context=policy)
            self.assertEqual(built["tombstone_count"], 1)
            result = projection.recall(
                "verified checkpoint",
                context=policy,
            )
            self.assertEqual(result["status"], "no_safe_match")
            self.assertIn(item_id, projection.export_manifest()["tombstoned_item_ids"])

    def test_delete_and_rebuild_yield_same_logical_manifest_and_query_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            policy = recall_policy(["global", "learning"])
            first = projection.build(context=policy)
            first_hits = projection.recall(
                "review rule",
                context=policy,
            )
            projection.index_path.unlink()
            second = projection.build(context=policy)
            second_hits = projection.recall(
                "review rule",
                context=policy,
            )
            self.assertEqual(first["projection_digest"], second["projection_digest"])
            self.assertEqual(
                [item["item_id"] for item in first_hits["matches"]],
                [item["item_id"] for item in second_hits["matches"]],
            )

    def test_explicit_lexical_fallback_ignores_tampered_index_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root, force_no_fts=True)
            policy = recall_policy(["global"])
            built = projection.build(context=policy)
            self.assertEqual(built["backend"], "sqlite_bounded_lexical")
            result = projection.recall(
                "deterministic review",
                context=policy,
            )
            self.assertEqual(result["status"], "hit")
            connection = sqlite3.connect(str(projection.index_path))
            try:
                connection.execute("UPDATE items SET authority_sha256 = ? WHERE authority_path = ?", ("0" * 64, "core/rule.md"))
                connection.commit()
            finally:
                connection.close()
            result = projection.recall(
                "deterministic review",
                context=policy,
            )
            self.assertEqual(result["status"], "hit")
            self.assertEqual(result["matches"][0]["authority_path"], "core/rule.md")
            self.assertEqual(
                result["matches"][0]["authority_sha256"],
                sha256_bytes((root / "core" / "rule.md").read_bytes()),
            )

    def test_tampered_projection_can_only_propose_id_and_never_redirect_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root, force_no_fts=True)
            policy = recall_policy(["global"])
            projection.build(context=policy)
            private = (root / "personal_knowledge" / "private.md").read_bytes()
            connection = sqlite3.connect(str(projection.index_path))
            try:
                connection.execute(
                    """UPDATE items
                       SET authority_path = ?, authority_sha256 = ?, scope = ?, lifecycle = ?, content = ?
                       WHERE authority_path = ?""",
                    (
                        "personal_knowledge/private.md",
                        sha256_bytes(private),
                        "global",
                        "active",
                        "deterministic review",
                        "core/rule.md",
                    ),
                )
                connection.commit()
            finally:
                connection.close()

            result = projection.recall(
                "deterministic review",
                context=policy,
            )

            self.assertEqual(result["status"], "hit")
            self.assertEqual(result["matches"][0]["authority_path"], "core/rule.md")
            self.assertNotIn("private forbidden marker", result["matches"][0]["evidence"])

    def test_invalid_tombstone_field_types_fail_closed_during_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            tombstones = root / "lifecycle" / "tombstones"
            tombstones.mkdir(parents=True)
            (tombstones / "invalid.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "tombstone_id": "tomb-invalid",
                        "item_id": ["learning-active"],
                        "authority_path": "learnings/active.md",
                        "authority_sha256": "0" * 64,
                        "reason": "invalid fixture",
                        "approval_receipt": "published-receipt-fixture",
                        "created_at": "2026-08-12T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            self.git(root, "add", "lifecycle/tombstones/invalid.json")
            self.git(root, "commit", "-m", "add invalid tombstone fixture")

            with self.assertRaisesRegex(ProjectionError, "invalid tombstone"):
                self.projection(root).build(context=recall_policy(["learning"]))

    def test_malformed_deleted_or_tombstone_metadata_cannot_be_coerced_to_false(self) -> None:
        for field in ("deleted", "tombstone"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_repository(root)
                (root / "core" / "malformed.md").write_text(
                    "---\nid: malformed-{0}\nstatus: active\n{0}: maybe\n---\n\n"
                    "malformedbooleanmarker\n".format(field),
                    encoding="utf-8",
                )
                self.git(root, "add", "core/malformed.md")
                self.git(root, "commit", "-m", "add malformed boolean fixture")

                with self.assertRaisesRegex(ProjectionError, "{} metadata is invalid".format(field)):
                    self.projection(root).build(context=recall_policy(["global"]))

    def test_query_limits_fail_before_projection_database_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)

            result = projection.recall(
                "oversized " + ("token " * 5000),
                context=recall_policy(["global"]),
            )

            self.assertEqual(result["status"], "no_safe_match")
            self.assertEqual(result["reason_codes"], ["query_too_large"])
            self.assertFalse(projection.index_path.exists())

    def test_bounded_lexical_fallback_searches_authority_beyond_500_item_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            for index in range(501):
                (root / "core" / "filler-{:04d}.md".format(index)).write_text(
                    "---\nid: filler-{:04d}\nstatus: active\nprivacy_class: public\n---\n\nordinary filler text\n".format(index),
                    encoding="utf-8",
                )
            (root / "core" / "zzz-target.md").write_text(
                "---\nid: zzz-target\nstatus: active\nprivacy_class: public\n---\n\nunique needle beyond five hundred\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core")
            self.git(root, "commit", "-m", "add large authority fixture")
            projection = self.projection(root, force_no_fts=True)
            policy = recall_policy(["global"])
            projection.build(context=policy)

            result = projection.recall(
                "unique needle beyond five hundred",
                context=policy,
            )

            self.assertEqual(result["status"], "hit")
            self.assertEqual(result["matches"][0]["item_id"], "zzz-target")

    def test_authority_corpus_budget_fails_explicitly_instead_of_truncating(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root, force_no_fts=True)

            with mock.patch.object(projection_module, "MAX_AUTHORITY_TOTAL_BYTES", 100):
                with self.assertRaisesRegex(ProjectionError, "authority_budget_exceeded"):
                    projection.build(context=recall_policy(["global"]))

    def test_ineligible_high_rank_matches_cannot_crowd_out_eligible_authority(self) -> None:
        for force_no_fts in (True, False):
            with self.subTest(force_no_fts=force_no_fts), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_repository(root)
                for index in range(205):
                    (root / "core" / "expired-crowd-{:04d}.md".format(index)).write_text(
                        "---\nid: expired-crowd-{:04d}\nstatus: active\nprivacy_class: public\n"
                        "valid_to: 2020-01-01T00:00:00Z\n---\n\n{}\n".format(
                            index,
                            "crowdingtoken " * 50,
                        ),
                        encoding="utf-8",
                    )
                (root / "core" / "zzz-eligible.md").write_text(
                    "---\nid: zzz-eligible\nstatus: active\nprivacy_class: public\n---\n\neligible crowdingtoken\n",
                    encoding="utf-8",
                )
                self.git(root, "add", "core")
                self.git(root, "commit", "-m", "add eligibility crowd fixture")
                projection = self.projection(root, force_no_fts=force_no_fts)
                policy = recall_policy(["global"])
                projection.build(context=policy)

                result = projection.recall(
                    "crowdingtoken",
                    context=policy,
                )

                self.assertEqual(result["status"], "hit")
                self.assertEqual(result["matches"][0]["item_id"], "zzz-eligible")

    def test_canonical_evidence_is_query_centered_and_line_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            late_marker = "LATE-CANONICAL-WINDOW-7319"
            (root / "core" / "late-window.md").write_text(
                "---\nid: late-window\nstatus: active\nprivacy_class: public\n---\n\n"
                "# Earlier material\n\n"
                + ("unrelated prefix text\n" * 450)
                + "\n## Verified late heading\n\n"
                + late_marker
                + " is the relevant canonical evidence.\n",
                encoding="utf-8",
            )
            self.git(root, "add", "core/late-window.md")
            self.git(root, "commit", "-m", "add canonical late window")
            projection = self.projection(root)
            policy = recall_policy(["global"])
            projection.build(context=policy)

            result = projection.recall(late_marker, context=policy)

            self.assertEqual("late-window", result["matches"][0]["item_id"])
            match = result["matches"][0]
            self.assertIn(late_marker, match["evidence"])
            self.assertNotIn("unrelated prefix text\n" * 200, match["evidence"])
            self.assertEqual("Verified late heading", match["heading"])
            self.assertRegex(
                match["source_ref"],
                r"^core/late-window\.md@[0-9a-f]{40}#L[0-9]+-L[0-9]+$",
            )
            self.assertLessEqual(len(match["evidence_content"]), 4000)

    def test_retention_is_deterministic_dry_run_without_physical_purge_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            projection.build(context=recall_policy(["global", "learning"]))
            plan = projection.plan_retention(as_of=datetime(2026, 8, 12, tzinfo=timezone.utc))
            self.assertTrue(plan["dry_run"])
            self.assertFalse(plan["physical_history_erasure"])
            actions = {item["item_id"]: item["action"] for item in plan["items"]}
            self.assertEqual(actions["learning-expired"], "propose_tombstone")
            self.assertEqual(actions["learning-superseded"], "review_superseded")
            self.assertNotIn("learning-active", actions)

    def test_retention_uses_fresh_committed_authority_not_mutable_or_stale_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_repository(root)
            projection = self.projection(root)
            projection.build(context=recall_policy(["global", "learning"]))
            connection = sqlite3.connect(str(projection.index_path))
            try:
                connection.execute(
                    "UPDATE items SET review_after = ? WHERE authority_path = ?",
                    ("2020-01-01T00:00:00Z", "core/rule.md"),
                )
                connection.commit()
            finally:
                connection.close()

            plan = projection.plan_retention(as_of=datetime(2026, 8, 12, tzinfo=timezone.utc))
            planned_ids = {item["item_id"] for item in plan["items"]}
            core_id = "doc_" + sha256_bytes(b"core/rule.md")[:24]
            self.assertNotIn(core_id, planned_ids)

            (root / "core" / "new.md").write_text("new committed authority\n", encoding="utf-8")
            self.git(root, "add", "core/new.md")
            self.git(root, "commit", "-m", "advance authority")
            with self.assertRaisesRegex(ProjectionError, "stale"):
                projection.plan_retention(as_of=datetime(2026, 8, 12, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
