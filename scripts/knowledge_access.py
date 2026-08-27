#!/usr/bin/env python3
"""Unified read-only access to governed knowledge and local recall layers.

The deterministic router and exact committed document remain authoritative.
Semantic and graph lanes may only propose bounded candidates; neither lane can
replace an authorized document or cross the private-profile boundary.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Optional

import retrieval_v2_knowledge_access as _implementation
from agent_memory_system.paths import (
    AUTHORITY_INDEX_PATH,
    EMBEDDING_CACHE_PATH,
    EMBEDDING_HELPER_PATH,
    HYBRID_INDEX_PATH,
    RUNTIME_ROOT,
)
from knowledge_router import ROOT as MEMORIES_ROOT
from knowledge_router import route_knowledge
from memory_control_plane.recall_policy import (
    RecallPolicy,
    load_recall_policy_file,
    verify_recall_request,
)


CODEX_HOME = MEMORIES_ROOT.parent
GRAPH_ROOT = CODEX_HOME / "memory-sidecar" / "indexes" / "knowledge-graphs"
MEMORY_PROJECTION = AUTHORITY_INDEX_PATH
HYBRID_MEMORY_PROJECTION = HYBRID_INDEX_PATH
AGENT_MEMORY_RUNTIME = RUNTIME_ROOT
AGENT_MEMORY_EMBEDDING_CACHE = EMBEDDING_CACHE_PATH
AGENT_MEMORY_EMBEDDING_HELPER = EMBEDDING_HELPER_PATH
TEXT_SUFFIXES = _implementation.TEXT_SUFFIXES
MAX_FILE_BYTES = _implementation.MAX_FILE_BYTES
MAX_GRAPH_BYTES = _implementation.MAX_GRAPH_BYTES
MAX_RECALL_FILES = _implementation.MAX_RECALL_FILES
MAX_RECALL_BYTES = _implementation.MAX_RECALL_BYTES
MAX_RECALL_PATHS_PER_LAYER = _implementation.MAX_RECALL_PATHS_PER_LAYER
GRAPH_BY_COLLECTION = _implementation.GRAPH_BY_COLLECTION


def access_knowledge(
    query: str,
    *,
    mode: str = "domain",
    root: Path = MEMORIES_ROOT,
    router_root: Path | None = None,
    codex_home: Path = CODEX_HOME,
    graph_root: Path = GRAPH_ROOT,
    strategy: str = "escalate",
    limit: int = 10,
    read_selector: Optional[str] = "first",
    expand_graph: bool = True,
    projection_path: Path = MEMORY_PROJECTION,
    hybrid_projection_path: Path = HYBRID_MEMORY_PROJECTION,
    recall_policy: RecallPolicy | dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _implementation._access_knowledge(
        query,
        profile=_implementation.LEGACY_ACCESS_PROFILE,
        route=route_knowledge,
        live_recall=_implementation.governed_live_recall,
        mode=mode,
        root=root,
        router_root=router_root,
        codex_home=codex_home,
        graph_root=graph_root,
        strategy=strategy,
        limit=limit,
        read_selector=read_selector,
        expand_graph=expand_graph,
        projection_path=projection_path,
        hybrid_projection_path=hybrid_projection_path,
        recall_policy=recall_policy,
        recall_scopes=("global", "platform", "learning"),
        high_stakes=False,
        embedding_helper=AGENT_MEMORY_EMBEDDING_HELPER,
        embedding_cache=AGENT_MEMORY_EMBEDDING_CACHE,
        verify_recall_request=verify_recall_request,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", nargs="+", help="query to retrieve")
    parser.add_argument(
        "--mode",
        choices=("domain", "durable", "policy", "history", "recent", "evidence"),
        default="domain",
    )
    parser.add_argument("--strategy", choices=("escalate", "all"), default="escalate")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--codex-home", type=Path, default=CODEX_HOME, help=argparse.SUPPRESS)
    parser.add_argument("--root", type=Path, default=MEMORIES_ROOT, help=argparse.SUPPRESS)
    parser.add_argument("--router-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--read", nargs="?", const="first", default="first")
    parser.add_argument("--no-graph", action="store_true")
    parser.add_argument("--recall-policy-file", type=Path)
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args()
    try:
        recall_policy = None
        if args.recall_policy_file is not None:
            recall_policy = load_recall_policy_file(args.recall_policy_file)
        result = access_knowledge(
            " ".join(args.query),
            mode=args.mode,
            root=args.root,
            router_root=args.router_root,
            codex_home=args.codex_home,
            strategy=args.strategy,
            limit=args.limit,
            read_selector=args.read,
            expand_graph=not args.no_graph,
            recall_policy=recall_policy,
        )
    except Exception:
        result = {"ok": False, "error": "knowledge access failed safely"}
        print(json.dumps(result, ensure_ascii=False))
        return 2
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    elif args.mode == "domain":
        route = result["route"]
        print(
            f"{route['decision']}: collection={route.get('collection_id') or '-'} "
            f"context={route.get('context_id') or '-'} graph={result['retrieval']['graph']['status']}"
        )
    else:
        print(result["summary"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
