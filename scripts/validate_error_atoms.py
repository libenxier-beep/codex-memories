#!/usr/bin/env python3
"""Validate standalone structured error atoms without rewriting the legacy handbook."""

from __future__ import annotations

import argparse
import json
import re
import stat
from datetime import date
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
ATOM_ROOT = Path("learnings/errors")
MAX_ATOM_BYTES = 64 * 1024
REQUIRED_FIELDS = {
    "schema_version",
    "error_id",
    "summary",
    "symptom",
    "root_cause",
    "prevention_guard",
    "verification",
    "source_incidents",
    "scope",
    "applies_to",
    "status",
    "first_seen",
    "last_seen",
    "recurrence_count",
    "review_condition",
    "supersedes",
}
IDENTIFIER = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)+$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def issue(path: Path, code: str) -> dict[str, str]:
    return {"path": path.as_posix(), "code": code}


def parse_date(value: object) -> Optional[date]:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def validate(root: Path = ROOT) -> list[dict[str, str]]:
    atom_root = root / ATOM_ROOT
    if not atom_root.exists():
        return []
    issues: list[dict[str, str]] = []
    seen: dict[str, Path] = {}
    for path in sorted(atom_root.glob("*.json")):
        relative = path.relative_to(root)
        try:
            metadata = path.lstat()
        except OSError:
            issues.append(issue(relative, "atom_unreadable"))
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            issues.append(issue(relative, "atom_not_regular"))
            continue
        if metadata.st_size > MAX_ATOM_BYTES:
            issues.append(issue(relative, "atom_too_large"))
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            issues.append(issue(relative, "atom_invalid_json"))
            continue
        if not isinstance(value, dict):
            issues.append(issue(relative, "schema_invalid"))
            continue
        if set(value) != REQUIRED_FIELDS or value.get("schema_version") != 1:
            issues.append(issue(relative, "schema_invalid"))
        error_id = value.get("error_id")
        if not isinstance(error_id, str) or IDENTIFIER.fullmatch(error_id) is None:
            issues.append(issue(relative, "error_id_invalid"))
        elif error_id in seen:
            issues.append(issue(relative, "duplicate_error_id"))
            issues.append(issue(seen[error_id].relative_to(root), "duplicate_error_id"))
        else:
            seen[error_id] = path
        for field in (
            "summary",
            "symptom",
            "root_cause",
            "prevention_guard",
            "verification",
            "review_condition",
        ):
            if not isinstance(value.get(field), str) or not str(value.get(field)).strip():
                issues.append(issue(relative, "schema_invalid"))
        if value.get("scope") not in {"global", "platform", "repo", "learning"}:
            issues.append(issue(relative, "scope_invalid"))
        if value.get("applies_to") not in {"all", "codex", "claude_code", "openclaw"}:
            issues.append(issue(relative, "applies_to_invalid"))
        if value.get("status") not in {"active", "superseded", "retired"}:
            issues.append(issue(relative, "status_invalid"))
        recurrence = value.get("recurrence_count")
        if isinstance(recurrence, bool) or not isinstance(recurrence, int) or recurrence < 1:
            issues.append(issue(relative, "recurrence_invalid"))
        supersedes = value.get("supersedes")
        if not isinstance(supersedes, list) or not all(isinstance(item, str) for item in supersedes):
            issues.append(issue(relative, "supersedes_invalid"))
        incidents = value.get("source_incidents")
        if not isinstance(incidents, list) or not incidents:
            issues.append(issue(relative, "source_incident_missing"))
        else:
            for incident in incidents:
                if not isinstance(incident, dict) or set(incident) != {"ref", "sha256"}:
                    issues.append(issue(relative, "source_incident_invalid"))
                    continue
                if not isinstance(incident.get("ref"), str) or not incident.get("ref"):
                    issues.append(issue(relative, "source_incident_invalid"))
                if not isinstance(incident.get("sha256"), str) or DIGEST.fullmatch(incident["sha256"]) is None:
                    issues.append(issue(relative, "source_digest_invalid"))
        first_seen = parse_date(value.get("first_seen"))
        last_seen = parse_date(value.get("last_seen"))
        if first_seen is None or last_seen is None:
            issues.append(issue(relative, "date_invalid"))
        elif first_seen > last_seen:
            issues.append(issue(relative, "time_order_invalid"))
    unique = {(item["path"], item["code"]): item for item in issues}
    return [unique[key] for key in sorted(unique)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--format", choices=("json", "text"), default="text")
    args = parser.parse_args()
    issues = validate(args.root)
    if args.format == "json":
        print(json.dumps({"ok": not issues, "issues": issues}, ensure_ascii=False, sort_keys=True))
    elif issues:
        for item in issues:
            print("{}: {}".format(item["path"], item["code"]))
    else:
        print("error atom validation passed")
    return 0 if not issues else 2


if __name__ == "__main__":
    raise SystemExit(main())
