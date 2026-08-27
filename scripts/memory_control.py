#!/usr/bin/env python3
"""Operate the local memory candidate and workspace-application control plane."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from memory_control_plane import (
    ControlPlaneError,
    MemoryControlPlane,
    SshHostAuthorizationVerifier,
    ValidatorSpec,
)
from agent_memory_system.governance import RuntimeDeletionCoordinator
from agent_memory_system.paths import AUTHORITY_INDEX_PATH, HYBRID_INDEX_PATH, STATE_PATH
from agent_memory_system.store import AgentMemoryStore, utc_now


ROOT = Path(__file__).resolve().parents[1]
MAX_JSON_INPUT_BYTES = 300 * 1024
MAX_STDIN_BYTES = MAX_JSON_INPUT_BYTES


def load_object(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("JSON input must be a regular file")
        if info.st_size > MAX_JSON_INPUT_BYTES:
            raise ValueError("JSON file exceeds the bounded input limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_JSON_INPUT_BYTES + 1)
        if len(raw) > MAX_JSON_INPUT_BYTES:
            raise ValueError("JSON file exceeds the bounded input limit")
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("input must contain one JSON object")
    return value


def load_candidate(value: str) -> dict[str, Any]:
    if value != "-":
        return load_object(Path(value))
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        raise ValueError("candidate stdin exceeds the bounded input limit")
    decoded = json.loads(raw.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("input must contain one JSON object")
    return decoded


def control_plane(
    root: Path,
    *,
    allow_honest_client_authorization: bool = False,
    host_allowed_signers: Path | None = None,
    host_allowed_signers_sha256: str | None = None,
) -> MemoryControlPlane:
    if (host_allowed_signers is None) != (host_allowed_signers_sha256 is None):
        raise ValueError("host allowed-signers path and digest must be supplied together")
    host_verifier = (
        SshHostAuthorizationVerifier(
            allowed_signers_path=host_allowed_signers,
            allowed_signers_sha256=host_allowed_signers_sha256,
        )
        if host_allowed_signers is not None
        and host_allowed_signers_sha256 is not None
        else None
    )
    return MemoryControlPlane(
        repository=root,
        control_root=root / "control_plane",
        repository_id="memories",
        policy_version="memory-control-plane-v1",
        allowed_subtrees=("core", "platform", "learnings", "lifecycle"),
        validators=(
            ValidatorSpec(
                name="memory-architecture",
                argv=(sys.executable, "scripts/validate_memory_architecture.py", "--format", "json"),
                timeout_seconds=60,
            ),
            ValidatorSpec(
                name="knowledge-collections",
                argv=(sys.executable, "scripts/validate_knowledge_collections.py", "--format", "json"),
                timeout_seconds=90,
            ),
            ValidatorSpec(
                name="knowledge-projection",
                argv=(sys.executable, "scripts/project_knowledge_routes.py"),
                timeout_seconds=60,
            ),
            ValidatorSpec(
                name="error-atoms",
                argv=(sys.executable, "scripts/validate_error_atoms.py", "--format", "json"),
                timeout_seconds=60,
            ),
            ValidatorSpec(
                name="control-and-read-contracts",
                argv=(
                    sys.executable,
                    "-m",
                    "unittest",
                    "tests.test_memory_control_plane",
                    "tests.test_knowledge_access",
                    "tests.test_immutable_knowledge_reader",
                ),
                timeout_seconds=180,
                max_output_bytes=65536,
            ),
        ),
        host_authorization_verifier=host_verifier,
        allow_honest_client_authorization=allow_honest_client_authorization,
    )


def runtime_deletion_coordinator(
    selected_root: Path, runtime_state_override: Path | None
) -> RuntimeDeletionCoordinator:
    selected_root = selected_root.resolve(strict=True)
    if runtime_state_override is not None:
        runtime_state = runtime_state_override.resolve(strict=False)
    elif selected_root == ROOT.resolve(strict=True):
        runtime_state = STATE_PATH
    else:
        runtime_state = selected_root / ".runtime" / "agent-memory.sqlite"
    index_paths = (
        (AUTHORITY_INDEX_PATH, HYBRID_INDEX_PATH)
        if selected_root == ROOT.resolve(strict=True)
        else (
            selected_root / ".runtime" / "authority.sqlite",
            selected_root / ".runtime" / "hybrid.sqlite",
        )
    )
    return RuntimeDeletionCoordinator(
        AgentMemoryStore(runtime_state),
        index_paths=index_paths,
    )


def replay_runtime_purge_obligations(
    recovery: dict[str, Any],
    *,
    selected_root: Path,
    runtime_state_override: Path | None,
) -> dict[str, Any]:
    obligations = list(recovery.pop("runtime_purge_obligations", []))
    purges = []
    if obligations:
        coordinator = runtime_deletion_coordinator(
            selected_root, runtime_state_override
        )
        for binding in obligations:
            purges.append(
                coordinator.purge_applied_tombstone(binding, now=utc_now())
            )
    recovery["runtime_purges"] = purges
    return recovery


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--root", type=Path, default=ROOT)
    root.add_argument("--host-allowed-signers", type=Path)
    root.add_argument("--host-allowed-signers-sha256")
    commands = root.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument(
        "--candidate",
        required=True,
        help="candidate JSON path, or '-' for bounded stdin",
    )
    prepare.add_argument("--gates", type=Path, required=True)

    assess = commands.add_parser("assess")
    assess.add_argument("--proposal", required=True)
    assess.add_argument("--assessment", type=Path, required=True)

    candidate_set = commands.add_parser("candidate-set")
    candidate_set.add_argument("proposal_ids", nargs="+")

    authorization_request = commands.add_parser("authorization-request")
    authorization_request.add_argument("--set-digest", required=True)
    authorization_request.add_argument("--evidence", type=Path, required=True)

    authorize = commands.add_parser("authorize")
    authorize.add_argument("--set-digest", required=True)
    authorize.add_argument("--evidence", type=Path, required=True)
    authorize.add_argument("--host-capability", type=Path, required=True)

    apply = commands.add_parser("apply-workspace")
    apply.add_argument("--proposal", required=True)
    apply.add_argument("--approval", required=True)
    apply.add_argument("--host-capability", type=Path, required=True)
    apply.add_argument("--runtime-state", type=Path)

    inspect = commands.add_parser("inspect")
    inspect_group = inspect.add_mutually_exclusive_group(required=True)
    inspect_group.add_argument("--proposal")
    inspect_group.add_argument("--audit", action="store_true")

    recover = commands.add_parser("recover")
    recover.add_argument("--host-capability", type=Path, required=True)
    recover.add_argument("--runtime-state", type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        capability_commands = {"authorize", "apply-workspace", "recover"}
        if args.command in capability_commands and (
            args.host_allowed_signers is None
            or args.host_allowed_signers_sha256 is None
        ):
            raise ValueError(
                "host allowed-signers path and digest are required for mutation"
            )
        plane = control_plane(
            args.root.resolve(strict=True),
            host_allowed_signers=args.host_allowed_signers,
            host_allowed_signers_sha256=args.host_allowed_signers_sha256,
        )
        if args.command == "prepare":
            result = plane.prepare(load_candidate(args.candidate), load_object(args.gates))
        elif args.command == "assess":
            result = plane.assess(args.proposal, load_object(args.assessment))
        elif args.command == "candidate-set":
            result = {"candidate_set_digest": plane.candidate_set(args.proposal_ids)}
        elif args.command == "authorization-request":
            result = plane.authorization_request(
                args.set_digest, load_object(args.evidence)
            )
        elif args.command == "authorize":
            result = plane.authorize(
                args.set_digest,
                load_object(args.evidence),
                host_capability=load_object(args.host_capability),
            )
        elif args.command == "apply-workspace":
            host_capability = load_object(args.host_capability)
            result = plane.apply_workspace(
                args.proposal,
                args.approval,
                host_capability=host_capability,
            )
            if result.get("operation") == "tombstone":
                binding = plane.applied_runtime_purge_binding(
                    args.proposal, str(result["receipt_id"])
                )
                if binding.get("owner") == "agent-memory-deletion-candidate":
                    selected_root = args.root.resolve(strict=True)
                    purge = runtime_deletion_coordinator(
                        selected_root, args.runtime_state
                    ).purge_applied_tombstone(
                        binding,
                        now=str(result["completed_at"]),
                    )
                    result = {**result, "runtime_purge": purge}
        elif args.command == "inspect":
            result = plane.audit() if args.audit else plane.inspect(args.proposal)
        elif args.command == "recover":
            result = replay_runtime_purge_obligations(
                dict(
                    plane.recover(
                        host_capability=load_object(args.host_capability)
                    )
                ),
                selected_root=args.root.resolve(strict=True),
                runtime_state_override=args.runtime_state,
            )
        else:
            raise AssertionError(args.command)
    except (ControlPlaneError, OSError, ValueError, json.JSONDecodeError) as error:
        code = error.code if isinstance(error, ControlPlaneError) else "input_error"
        print(json.dumps({"ok": False, "error": {"code": code, "message": str(error)}}, ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
