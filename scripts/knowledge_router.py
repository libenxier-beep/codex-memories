#!/usr/bin/env python3
"""Legacy-compatible adapter for the authoritative retrieval v2 router."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

# Preserve the baseline module's observable namespace for this compatibility
# window. These re-exports are legacy-only, not canonical API, and retire with
# this adapter.
from retrieval_v2_knowledge_router import (
    CURRENT_SOURCE_SAFETY_DIRECT_SIGNALS,
    CURRENT_SOURCE_SAFETY_DYNAMIC_TOPICS,
    CURRENT_SOURCE_SAFETY_TEMPORAL_SIGNALS,
    EVAL_PATH,
    FIRST_PERSON_SIGNALS,
    FORBIDDEN_COLLECTION_FRAGMENTS,
    GENERIC_PRIVATE_MODELING_SIGNALS,
    GLOBAL_ROOT_SIGNALS,
    MAX_SNAPSHOT_FILES,
    PERSONAL_ROOT_SIGNALS,
    PRIVATE_DIRECT_SIGNALS,
    PRIVATE_FACT_SIGNALS,
    PRIVATE_MEMORY_ACCESS_SIGNALS,
    PRIVATE_MEMORY_LABEL_SIGNALS,
    PRIVATE_MEMORY_USE_SIGNALS,
    PRIVATE_STORE_SIGNALS,
    REGISTRY_PATH,
    ROOT,
    WORK_ROOT_SIGNALS,
    CollectionSource,
    Iterator,
    ModuleType,
    PurePosixPath,
    contextmanager,
    csv,
    dataclass,
    date,
    hashlib,
    io,
    json,
    load_collection_registry,
    os,
    re,
    replace,
    shutil,
    stat,
    subprocess,
    tempfile,
    unicodedata,
    LEGACY_MAX_GIT_BATCH_INPUT_BYTES as _LEGACY_MAX_GIT_BATCH_INPUT_BYTES,
    LEGACY_MAX_GIT_BATCH_OUTPUT_BYTES as _LEGACY_MAX_GIT_BATCH_OUTPUT_BYTES,
    LEGACY_MAX_SNAPSHOT_BYTES as _LEGACY_MAX_SNAPSHOT_BYTES,
    LEGACY_ROUTER_PROFILE as _LEGACY_ROUTER_PROFILE,
    _evaluate_knowledge_routes,
    _resolve_collection_source,
    _resolve_collection_sources,
    _route_knowledge,
)


# Preserve the legacy module's observable budget constants while the shared
# owner keeps the larger v2 snapshot allowance as its default.
MAX_SNAPSHOT_BYTES = _LEGACY_MAX_SNAPSHOT_BYTES
MAX_GIT_BATCH_INPUT_BYTES = _LEGACY_MAX_GIT_BATCH_INPUT_BYTES
MAX_GIT_BATCH_OUTPUT_BYTES = _LEGACY_MAX_GIT_BATCH_OUTPUT_BYTES


def resolve_collection_sources(
    root: Path,
    registry: dict[str, Any],
) -> dict[str, CollectionSource]:  # noqa: F405
    return _resolve_collection_sources(
        root,
        registry,
        profile=_LEGACY_ROUTER_PROFILE,
    )


def resolve_collection_source(
    root: Path,
    collection: dict[str, Any],
) -> CollectionSource:  # noqa: F405
    return _resolve_collection_source(
        root,
        collection,
        profile=_LEGACY_ROUTER_PROFILE,
    )


def route_knowledge(
    query: str,
    root: Path = ROOT,  # noqa: F405
    *,
    read_selector: Optional[str] = None,
) -> dict[str, Any]:
    return _route_knowledge(
        query,
        root=root,
        read_selector=read_selector,
        profile=_LEGACY_ROUTER_PROFILE,
    )


def evaluate_knowledge_routes(root: Path = ROOT) -> dict[str, Any]:  # noqa: F405
    return _evaluate_knowledge_routes(root, profile=_LEGACY_ROUTER_PROFILE)
