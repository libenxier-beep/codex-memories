"""Choose the governed query-classification adapter for a deployment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

from knowledge_router import route_knowledge
from memory_control_plane.repository import (
    _governed_git_environment,
    _repository_git_binding,
    _trusted_git_executable,
)
from retrieval_v2_knowledge_router import is_private_profile_request


LOCAL_AUTHORITY_ROUTER_VERSION = "codex-memories-local-authority-router-v1"


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def route_local_authority(query: str, *, root: Path) -> dict[str, Any]:
    """Bind a query to one local Git authority without collection routing."""

    if not isinstance(query, str) or not query.strip() or "\x00" in query:
        raise ValueError("query must be non-empty text")
    repository, git_dir, common_dir = _repository_git_binding(root)
    environment = _governed_git_environment()
    environment.update(
        {
            "GIT_DIR": str(git_dir),
            "GIT_WORK_TREE": str(repository),
            "GIT_COMMON_DIR": str(common_dir),
        }
    )
    completed = subprocess.run(
        [_trusted_git_executable(), "rev-parse", "HEAD^{commit}"],
        cwd=repository,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("local authority must have a committed HEAD")
    revision = completed.stdout.strip()
    registry_digest = hashlib.sha256(LOCAL_AUTHORITY_ROUTER_VERSION.encode("utf-8")).hexdigest()
    source_set_digest = _digest(
        {"repository_revision": revision, "router": LOCAL_AUTHORITY_ROUTER_VERSION}
    )
    binding_body = {
        "schema_version": 1,
        "parent_revision": revision,
        "registry_sha256": registry_digest,
        "source_count": 1,
        "source_set_sha256": source_set_digest,
    }
    return {
        "decision": "private_profile" if is_private_profile_request(query) else "local_authority",
        "collection_id": None,
        "context_id": None,
        "query_fingerprint": hashlib.sha256(query.encode("utf-8")).hexdigest()[:16],
        "trace": {
            "stage": "privacy_boundary"
            if is_private_profile_request(query)
            else "collection_root",
            "router": LOCAL_AUTHORITY_ROUTER_VERSION,
        },
        "authority_binding": {
            **binding_body,
            "binding_sha256": _digest(binding_body),
        },
    }


def route_memory_query(
    query: str,
    *,
    root: Path,
    profile: str = "auto",
) -> dict[str, Any]:
    """Route through collection governance when present, otherwise local authority."""

    if profile not in {"auto", "collections", "local-authority"}:
        raise ValueError("unsupported router profile")
    selected = profile
    if selected == "auto":
        selected = "collections" if (root / "knowledge_collections.registry.json").is_file() else "local-authority"
    if selected == "collections":
        return route_knowledge(query, root=root, read_selector=None)
    return route_local_authority(query, root=root)
