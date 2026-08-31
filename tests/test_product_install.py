from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "codex_memories.py"


class ProductInstallTests(unittest.TestCase):
    def run_installer(self, *args: str) -> dict:
        completed = subprocess.run(
            [sys.executable, str(INSTALLER), *args, "--format", "json"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        return json.loads(completed.stdout)

    def install(self, root: Path) -> tuple[Path, Path, Path]:
        prefix = root / "app"
        authority = root / "private-authority"
        codex_home = root / "codex-home"
        result = self.run_installer(
            "install",
            "--prefix",
            str(prefix),
            "--authority",
            str(authority),
            "--codex-home",
            str(codex_home),
            "--skip-index",
        )
        self.assertEqual(result["status"], "installed")
        return prefix, authority, codex_home

    def test_shell_entrypoint_exposes_the_guided_installer(self) -> None:
        completed = subprocess.run(
            ["/bin/sh", str(ROOT / "install.sh"), "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn("--prefix", completed.stdout)
        self.assertIn("--authority", completed.stdout)
        self.assertIn("--codex-home", completed.stdout)

    def test_install_creates_an_isolated_runtime_and_review_only_hook_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            prefix, authority, codex_home = self.install(Path(temporary))

            launcher = prefix / "bin" / "codex-memories"
            plan = json.loads((prefix / "hooks.merge-plan.json").read_text(encoding="utf-8"))
            manifest = json.loads((prefix / "install.json").read_text(encoding="utf-8"))

            self.assertTrue(os.access(launcher, os.X_OK))
            self.assertTrue((prefix / "runtime" / "scripts" / "agent_memory.py").is_file())
            self.assertTrue((authority / ".git").is_dir())
            self.assertTrue((authority / "core" / "welcome.md").is_file())
            self.assertTrue((authority / "platform").is_dir())
            self.assertTrue((authority / "learnings").is_dir())
            tracked = subprocess.run(
                ["git", "ls-files"],
                cwd=authority,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(tracked.returncode, 0, tracked.stderr)
            self.assertIn("platform/.gitkeep", tracked.stdout.splitlines())
            self.assertIn("learnings/.gitkeep", tracked.stdout.splitlines())
            self.assertFalse((codex_home / "hooks.json").exists())
            self.assertEqual(plan["operation"], "merge_plan_only")
            self.assertEqual(len(plan["added_events"]), 6)
            hook_command = plan["merged"]["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
            self.assertIn(str(launcher), hook_command)
            self.assertIn("--router-profile local-authority", hook_command)
            self.assertEqual(manifest["authority"], str(authority.resolve()))
            self.assertEqual(manifest["codex_home"], str(codex_home.resolve()))

    def test_reinstall_preserves_user_memory_and_doctor_reports_next_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix, authority, _codex_home = self.install(root)
            user_memory = authority / "core" / "my-rule.md"
            user_memory.write_text("user-owned\n", encoding="utf-8")

            self.run_installer(
                "install",
                "--prefix",
                str(prefix),
                "--authority",
                str(authority),
                "--codex-home",
                str(root / "codex-home"),
                "--skip-index",
            )
            self.assertEqual(user_memory.read_text(encoding="utf-8"), "user-owned\n")

            completed = subprocess.run(
                [str(prefix / "bin" / "codex-memories"), "doctor", "--format", "json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
            report = json.loads(completed.stdout)
            self.assertTrue(report["ready"])
            self.assertEqual(report["integration"], "review_required")
            self.assertEqual(report["checks"]["authority_git"], "pass")
            self.assertEqual(report["checks"]["hook_plan"], "pass")

    def test_existing_collection_authority_keeps_the_advanced_router(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority = root / "authority"
            authority.mkdir()
            for directory in ("core", "platform", "learnings"):
                (authority / directory).mkdir()
            (authority / "knowledge_collections.registry.json").write_text(
                '{"schema_version":1}\n', encoding="utf-8"
            )
            for command in (
                ["git", "init", "-b", "main"],
                ["git", "add", "."],
                [
                    "git",
                    "-c",
                    "user.name=Synthetic Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "Initialize synthetic authority",
                ],
            ):
                completed = subprocess.run(
                    command,
                    cwd=authority,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            prefix = root / "app"
            self.run_installer(
                "install",
                "--prefix",
                str(prefix),
                "--authority",
                str(authority),
                "--codex-home",
                str(root / "codex-home"),
                "--skip-index",
            )
            manifest = json.loads((prefix / "install.json").read_text(encoding="utf-8"))
            plan = json.loads((prefix / "hooks.merge-plan.json").read_text(encoding="utf-8"))
            command = plan["merged"]["hooks"]["SessionStart"][0]["hooks"][0]["command"]

            self.assertEqual(manifest["router_profile"], "collections")
            self.assertIn("--router-profile collections", command)

    def test_install_rejects_a_directory_nested_inside_another_git_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "parent-repository"
            authority = parent / "nested-authority"
            authority.mkdir(parents=True)
            (authority / "memory.md").write_text("synthetic\n", encoding="utf-8")
            initialized = subprocess.run(
                ["git", "init", "-b", "main"],
                cwd=parent,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(INSTALLER),
                    "install",
                    "--prefix",
                    str(root / "app"),
                    "--authority",
                    str(authority),
                    "--codex-home",
                    str(root / "codex-home"),
                    "--skip-index",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("repository root", json.loads(completed.stdout)["error"]["message"])

    def test_reinstall_replaces_the_generated_runtime_without_stale_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix, authority, codex_home = self.install(root)
            stale = prefix / "runtime" / "scripts" / "removed-in-upgrade.py"
            stale.write_text("obsolete\n", encoding="utf-8")

            self.run_installer(
                "install",
                "--prefix",
                str(prefix),
                "--authority",
                str(authority),
                "--codex-home",
                str(codex_home),
                "--skip-index",
            )

            self.assertFalse(stale.exists())

    def test_local_authority_profile_recalls_without_a_collection_registry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prefix, authority, _codex_home = self.install(root)
            launcher = prefix / "bin" / "codex-memories"

            indexed = subprocess.run(
                [str(launcher), "index"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(indexed.returncode, 0, indexed.stderr or indexed.stdout)
            recalled = subprocess.run(
                [str(launcher), "recall", "governed local memory", "--limit", "3"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(recalled.returncode, 0, recalled.stderr or recalled.stdout)
            payload = json.loads(recalled.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["result"]["status"], "hit")
            self.assertTrue(
                any("installation is active" in item["evidence"] for item in payload["result"]["matches"])
            )


if __name__ == "__main__":
    unittest.main()
