from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_error_atoms  # noqa: E402


class ErrorAtomValidationTests(unittest.TestCase):
    def valid_atom(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "error_id": "error.fixture.prevent-repeat",
            "summary": "A repeated fixture failure needs a durable guard.",
            "symptom": "The same invalid transition was attempted twice.",
            "root_cause": "The public seam did not enforce the precondition.",
            "prevention_guard": "Reject the transition before mutation.",
            "verification": "The adversarial transition test remains green.",
            "source_incidents": [
                {"ref": "rollout:fixture", "sha256": "a" * 64}
            ],
            "scope": "learning",
            "applies_to": "all",
            "status": "active",
            "first_seen": "2026-08-01",
            "last_seen": "2026-08-12",
            "recurrence_count": 2,
            "review_condition": "Retire after two independent releases without recurrence.",
            "supersedes": [],
        }

    def test_valid_error_atom_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atoms = root / "learnings" / "errors"
            atoms.mkdir(parents=True)
            (atoms / "fixture.json").write_text(json.dumps(self.valid_atom()), encoding="utf-8")
            self.assertEqual(validate_error_atoms.validate(root), [])

    def test_missing_guard_invalid_digest_and_time_order_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atoms = root / "learnings" / "errors"
            atoms.mkdir(parents=True)
            value = self.valid_atom()
            del value["prevention_guard"]
            value["source_incidents"] = [{"ref": "rollout:fixture", "sha256": "not-a-digest"}]
            value["first_seen"] = "2026-08-13"
            value["last_seen"] = "2026-08-12"
            (atoms / "fixture.json").write_text(json.dumps(value), encoding="utf-8")
            issues = validate_error_atoms.validate(root)
            codes = {issue["code"] for issue in issues}
            self.assertIn("schema_invalid", codes)
            self.assertIn("source_digest_invalid", codes)
            self.assertIn("time_order_invalid", codes)

    def test_duplicate_ids_and_unknown_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            atoms = root / "learnings" / "errors"
            atoms.mkdir(parents=True)
            first = self.valid_atom()
            second = self.valid_atom()
            second["unexpected"] = "future ambiguity"
            (atoms / "first.json").write_text(json.dumps(first), encoding="utf-8")
            (atoms / "second.json").write_text(json.dumps(second), encoding="utf-8")
            issues = validate_error_atoms.validate(root)
            codes = {issue["code"] for issue in issues}
            self.assertIn("duplicate_error_id", codes)
            self.assertIn("schema_invalid", codes)

    def test_repository_cli_passes_current_empty_atom_collection(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/validate_error_atoms.py", "--format", "json"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
