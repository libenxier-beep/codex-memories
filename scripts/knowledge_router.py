#!/usr/bin/env python3
"""Legacy-compatible adapter for the authoritative retrieval v2 router."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from retrieval_v2_knowledge_router import *  # noqa: F403
from retrieval_v2_knowledge_router import (
    LEGACY_MAX_GIT_BATCH_INPUT_BYTES,
    LEGACY_MAX_GIT_BATCH_OUTPUT_BYTES,
    LEGACY_MAX_SNAPSHOT_BYTES,
    LEGACY_ROUTER_PROFILE,
    _evaluate_knowledge_routes,
    _resolve_collection_source,
    _resolve_collection_sources,
    _route_knowledge,
)


# Preserve the legacy module's observable budget constants while the shared
# owner keeps the larger v2 snapshot allowance as its default.
MAX_SNAPSHOT_BYTES = LEGACY_MAX_SNAPSHOT_BYTES
MAX_GIT_BATCH_INPUT_BYTES = LEGACY_MAX_GIT_BATCH_INPUT_BYTES
MAX_GIT_BATCH_OUTPUT_BYTES = LEGACY_MAX_GIT_BATCH_OUTPUT_BYTES


def resolve_collection_sources(
    root: Path,
    registry: dict[str, Any],
) -> dict[str, CollectionSource]:  # noqa: F405
    return _resolve_collection_sources(
        root,
        registry,
        profile=LEGACY_ROUTER_PROFILE,
    )


def resolve_collection_source(
    root: Path,
    collection: dict[str, Any],
) -> CollectionSource:  # noqa: F405
    return _resolve_collection_source(
        root,
        collection,
        profile=LEGACY_ROUTER_PROFILE,
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
        profile=LEGACY_ROUTER_PROFILE,
    )


def evaluate_knowledge_routes(root: Path = ROOT) -> dict[str, Any]:  # noqa: F405
    return _evaluate_knowledge_routes(root, profile=LEGACY_ROUTER_PROFILE)
