#!/usr/bin/env python3
"""Install and diagnose an isolated Codex Memories deployment."""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ALLOWLIST = (
    "scripts",
    "schemas",
    "memory_schema.md",
    "memory_intake_checklist.md",
)


def _atomic_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".codex-memories-", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            descriptor = -1
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _ensure_safe_directory(path: Path, *, label: str) -> Path:
    resolved = Path(os.path.abspath(str(path))).resolve(strict=False)
    if resolved == Path(resolved.anchor):
        raise ValueError("{} cannot be a filesystem root".format(label))
    if path.exists() and stat.S_ISLNK(path.lstat().st_mode):
        raise ValueError("{} cannot be a symlink".format(label))
    return resolved


def _copy_runtime(prefix: Path) -> Path:
    runtime = prefix / "runtime"
    staging = Path(tempfile.mkdtemp(prefix=".runtime-staging-", dir=str(prefix)))
    ignored = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")
    try:
        for relative in RUNTIME_ALLOWLIST:
            source = SOURCE_ROOT / relative
            destination = staging / relative
            if source.is_dir():
                shutil.copytree(source, destination, ignore=ignored)
            else:
                shutil.copy2(source, destination)
        previous = prefix / "runtime.previous"
        if previous.exists():
            if previous.is_symlink() or not previous.is_dir():
                raise ValueError("runtime.previous must be a generated directory")
            shutil.rmtree(previous)
        if runtime.exists():
            if runtime.is_symlink() or not runtime.is_dir():
                raise ValueError("runtime must be a generated directory")
            os.replace(runtime, previous)
        try:
            os.replace(staging, runtime)
        except Exception:
            if previous.exists() and not runtime.exists():
                os.replace(previous, runtime)
            raise
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return runtime


def _git(authority: Path, *args: str) -> subprocess.CompletedProcess[str]:
    executable = next(
        (
            candidate
            for candidate in ("/usr/bin/git", "/bin/git")
            if Path(candidate).is_file() and os.access(candidate, os.X_OK)
        ),
        shutil.which("git", path=os.defpath),
    )
    if executable is None or not os.path.isabs(executable):
        raise ValueError("Git is required")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
    }
    return subprocess.run(
        [executable, *args],
        cwd=authority,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _starter_memory() -> str:
    today = date.today().isoformat()
    return """---
id: codex-memories-welcome
title: Codex Memories is active
summary: Confirms that governed local memory is installed and recallable.
scope: global
applies_to: codex
type: config
stability: high
authorization_state: user_approved
provenance_trust: current_source_validated
privacy_class: private_local
source: local_install
evidence: installer_created
regression_risk: low
supersedes: []
last_reviewed: {today}
owner: local-user
status: active
---

# Welcome

Codex Memories installation is active. This governed local memory is stored in
your private Git authority and can be replaced with your own durable rules.
""".format(today=today)


def _initialize_authority(authority: Path) -> str:
    if authority.exists() and any(authority.iterdir()):
        probe = _git(authority, "rev-parse", "--is-inside-work-tree")
        if probe.returncode != 0 or probe.stdout.strip() != "true":
            raise ValueError("an existing authority must be a Git repository")
        top = _git(authority, "rev-parse", "--show-toplevel")
        if top.returncode != 0 or Path(top.stdout.strip()).resolve(strict=True) != authority:
            raise ValueError("an existing authority must be the Git repository root")
        return "preserved"

    authority.mkdir(mode=0o700, parents=True, exist_ok=True)
    for directory in ("core", "platform", "learnings"):
        (authority / directory).mkdir(mode=0o700, exist_ok=True)
    for directory in ("platform", "learnings"):
        keep = authority / directory / ".gitkeep"
        keep.write_text("", encoding="utf-8")
        os.chmod(keep, 0o600)
    welcome = authority / "core" / "welcome.md"
    welcome.write_text(_starter_memory(), encoding="utf-8")
    os.chmod(welcome, 0o600)
    ignore = authority / ".gitignore"
    ignore.write_text("memory-sidecar/\n*.sqlite\n*.sqlite-*\n.DS_Store\n", encoding="utf-8")
    initialized = _git(authority, "init", "-b", "main")
    if initialized.returncode != 0:
        raise ValueError("Git authority initialization failed: " + initialized.stderr.strip())
    staged = _git(authority, "add", ".gitignore", "core", "platform", "learnings")
    if staged.returncode != 0:
        raise ValueError("Git authority staging failed: " + staged.stderr.strip())
    committed = _git(
        authority,
        "-c",
        "user.name=Codex Memories Installer",
        "-c",
        "user.email=installer@codex-memories.local",
        "commit",
        "-m",
        "Initialize private Codex Memories authority",
    )
    if committed.returncode != 0:
        raise ValueError("Git authority commit failed: " + committed.stderr.strip())
    return "created"


def _launcher_source() -> str:
    return '''#!/usr/bin/env python3
from __future__ import annotations
import json
import os
from pathlib import Path
import sys

prefix = Path(__file__).resolve().parents[1]
manifest_path = prefix / "install.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
runtime = prefix / "runtime"
if len(sys.argv) > 1 and sys.argv[1] == "doctor":
    command = [sys.executable, str(runtime / "scripts" / "codex_memories.py"), "doctor", "--manifest", str(manifest_path), *sys.argv[2:]]
else:
    sidecar = Path(manifest["codex_home"]) / "memory-sidecar"
    command = [
        sys.executable,
        str(runtime / "scripts" / "agent_memory.py"),
        "--state", str(sidecar / "agent-memory-v1" / "agent-memory.sqlite"),
        "--root", manifest["authority"],
        "--router-root", manifest["authority"],
        "--router-profile", manifest["router_profile"],
        "--authority-index", str(sidecar / "indexes" / "memory-control-v1.sqlite"),
        "--hybrid-index", str(sidecar / "indexes" / "agent-memory-hybrid-v1.sqlite"),
        "--embedding-cache", str(sidecar / "agent-memory-v1" / "embedding-cache"),
        "--recall-policy-profile", "local-work",
        *sys.argv[1:],
    ]
os.execv(sys.executable, command)
'''


def _write_launcher(prefix: Path) -> Path:
    launcher = prefix / "bin" / "codex-memories"
    launcher.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    launcher.write_text(_launcher_source(), encoding="utf-8")
    os.chmod(launcher, 0o700)
    return launcher


def _read_hooks(codex_home: Path) -> dict[str, object]:
    hooks_path = codex_home / "hooks.json"
    if not hooks_path.exists():
        return {"hooks": {}}
    if hooks_path.is_symlink() or not hooks_path.is_file() or hooks_path.stat().st_size > 1024 * 1024:
        raise ValueError("hooks.json must be a bounded regular file")
    value = json.loads(hooks_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("hooks.json must contain an object")
    return value


def install(args: argparse.Namespace) -> dict[str, Any]:
    prefix = _ensure_safe_directory(args.prefix, label="prefix")
    authority = _ensure_safe_directory(args.authority, label="authority")
    codex_home = _ensure_safe_directory(args.codex_home, label="codex home")
    if prefix == authority or prefix in authority.parents or authority in prefix.parents:
        raise ValueError("runtime prefix and private authority must be separate")
    prefix.mkdir(mode=0o700, parents=True, exist_ok=True)
    codex_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime = _copy_runtime(prefix)
    authority_status = _initialize_authority(authority)
    router_profile = (
        "collections"
        if (authority / "knowledge_collections.registry.json").is_file()
        else "local-authority"
    )
    launcher = _write_launcher(prefix)
    manifest = {
        "schema_version": 1,
        "product": "Codex Memories",
        "prefix": str(prefix),
        "runtime": str(runtime),
        "authority": str(authority),
        "codex_home": str(codex_home),
        "router_profile": router_profile,
        "recall_policy_profile": "local-work",
    }
    _atomic_json(prefix / "install.json", manifest)

    sys.path.insert(0, str(runtime / "scripts"))
    from agent_memory_system.hooks import build_hooks_merge_plan

    hook_command = shlex.join(
        [str(launcher), "--router-profile", router_profile, "hook"]
    )
    plan = build_hooks_merge_plan(
        _read_hooks(codex_home), command=hook_command, timeout_seconds=30
    )
    _atomic_json(prefix / "hooks.merge-plan.json", plan)

    index_status = "skipped"
    if not args.skip_index:
        indexed = subprocess.run(
            [str(launcher), "index"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if indexed.returncode != 0:
            raise ValueError("initial index failed: " + (indexed.stderr or indexed.stdout).strip())
        index_status = "ready"
    return {
        "status": "installed",
        "authority": authority_status,
        "index": index_status,
        "launcher": str(launcher),
        "hook_plan": str(prefix / "hooks.merge-plan.json"),
        "next_action": "Review and merge hooks.merge-plan.json with the owner of your Codex hooks configuration.",
    }


def _git_ready(authority: Path) -> bool:
    if not authority.is_dir():
        return False
    probe = _git(authority, "rev-parse", "HEAD^{commit}")
    top = _git(authority, "rev-parse", "--show-toplevel")
    return (
        probe.returncode == 0
        and bool(probe.stdout.strip())
        and top.returncode == 0
        and Path(top.stdout.strip()).resolve(strict=True) == authority.resolve(strict=True)
    )


def doctor(args: argparse.Namespace) -> dict[str, Any]:
    manifest_path = args.manifest.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    prefix = Path(manifest["prefix"])
    authority = Path(manifest["authority"])
    codex_home = Path(manifest["codex_home"])
    checks = {
        "runtime": "pass" if (prefix / "runtime" / "scripts" / "agent_memory.py").is_file() else "fail",
        "launcher": "pass" if os.access(prefix / "bin" / "codex-memories", os.X_OK) else "fail",
        "authority_git": "pass" if _git_ready(authority) else "fail",
        "authority_roots": "pass"
        if all((authority / item).is_dir() for item in ("core", "platform", "learnings"))
        else "fail",
        "hook_plan": "pass" if (prefix / "hooks.merge-plan.json").is_file() else "fail",
    }
    integration = "review_required"
    hooks_path = codex_home / "hooks.json"
    if hooks_path.is_file() and (prefix / "hooks.merge-plan.json").is_file():
        current = json.loads(hooks_path.read_text(encoding="utf-8"))
        plan = json.loads((prefix / "hooks.merge-plan.json").read_text(encoding="utf-8"))
        if current == plan.get("merged"):
            integration = "active"
    return {
        "ready": all(value == "pass" for value in checks.values()),
        "integration": integration,
        "checks": checks,
        "next_action": None
        if integration == "active"
        else "Review the generated hook plan before changing Codex hooks.json.",
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    install_command = commands.add_parser("install", help="install an isolated local deployment")
    install_command.add_argument(
        "--prefix", type=Path, default=Path("~/.local/share/codex-memories").expanduser()
    )
    install_command.add_argument(
        "--authority", type=Path, default=Path("~/.codex/memories").expanduser()
    )
    install_command.add_argument(
        "--codex-home",
        type=Path,
        default=Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser(),
    )
    install_command.add_argument("--skip-index", action="store_true")
    install_command.add_argument("--format", choices=("text", "json"), default="text")

    doctor_command = commands.add_parser("doctor", help="verify an installed deployment")
    doctor_command.add_argument("--manifest", type=Path, required=True)
    doctor_command.add_argument("--format", choices=("text", "json"), default="text")
    return root


def _render_text(result: dict[str, Any]) -> str:
    if "ready" in result:
        state = "ready" if result["ready"] else "needs attention"
        return "Codex Memories: {}\nIntegration: {}\nNext: {}".format(
            state, result["integration"], result.get("next_action") or "none"
        )
    return "Codex Memories installed.\nCommand: {}\nNext: {}".format(
        result["launcher"], result["next_action"]
    )


def main() -> int:
    args = parser().parse_args()
    try:
        result = install(args) if args.command == "install" else doctor(args)
    except Exception as error:
        failure = {"ok": False, "error": {"code": type(error).__name__, "message": str(error)}}
        print(json.dumps(failure, ensure_ascii=False, sort_keys=True))
        return 2
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(_render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
