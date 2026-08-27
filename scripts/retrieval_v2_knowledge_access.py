#!/usr/bin/env python3
"""Unified read-only access to governed knowledge and local recall layers.

The deterministic router and exact committed document remain authoritative.
Semantic and graph lanes may only propose bounded candidates; neither lane can
replace an authorized document or cross the private-profile boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from retrieval_v2_knowledge_router import ROOT as MEMORIES_ROOT
from retrieval_v2_knowledge_router import route_knowledge
from retrieval.live import governed_live_recall


CODEX_HOME = MEMORIES_ROOT.parent
GRAPH_ROOT = CODEX_HOME / "memory-sidecar" / "indexes" / "knowledge-graphs"
MEMORY_PROJECTION = CODEX_HOME / "memory-sidecar" / "indexes" / "memory-control-v1.sqlite"
TEXT_SUFFIXES = {".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".toml"}
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_GRAPH_BYTES = 32 * 1024 * 1024
MAX_RECALL_FILES = 2000
MAX_RECALL_BYTES = 64 * 1024 * 1024
MAX_RECALL_PATHS_PER_LAYER = 10000
MIN_GRAPH_CANDIDATE_SCORE = 8.0
GRAPH_BY_COLLECTION = {
    "work": "work-contexts-routing",
    "personal_knowledge": "personal-knowledge-routing",
}


@dataclass(frozen=True)
class AccessProfile:
    legacy_durable: bool
    graph_context_discovery: bool
    live_semantic_recall: bool


V2_ACCESS_PROFILE = AccessProfile(
    legacy_durable=False,
    graph_context_discovery=True,
    live_semantic_recall=True,
)
LEGACY_ACCESS_PROFILE = AccessProfile(
    legacy_durable=True,
    graph_context_discovery=False,
    live_semantic_recall=False,
)


def _configured_layers(root: Path, mode: str) -> list[tuple[str, list[Path]]]:
    return {
        "policy": [
            ("memories/core", [root / "memories" / "core"]),
            ("memories/platform", [root / "memories" / "platform"]),
        ],
        "history": [
            ("memories/MEMORY.md", [root / "memories" / "MEMORY.md"]),
            ("memories/rollout_summaries", [root / "memories" / "rollout_summaries"]),
        ],
        "recent": [
            ("memory-sidecar/indexes", [root / "memory-sidecar" / "indexes"]),
            ("memory-sidecar/sessions", [root / "memory-sidecar" / "sessions"]),
            ("sessions", [root / "sessions"]),
            ("memories/rollout_summaries", [root / "memories" / "rollout_summaries"]),
        ],
        "evidence": [
            ("memory-sidecar/sessions", [root / "memory-sidecar" / "sessions"]),
            ("memory-sidecar/evidence", [root / "memory-sidecar" / "evidence"]),
            ("memories/evidence", [root / "memories" / "evidence"]),
        ],
    }[mode]


def _iter_files(paths: Iterable[Path], root: Path) -> Iterable[Path]:
    root = root.resolve()
    seen: set[Path] = set()
    for path in paths:
        if not path.exists() or path.is_symlink():
            continue
        configured = path.resolve()
        configured_is_file = configured.is_file()
        candidates = [path] if configured_is_file else path.rglob("*")
        inspected = 0
        for candidate in candidates:
            inspected += 1
            if inspected > MAX_RECALL_PATHS_PER_LAYER:
                break
            try:
                if candidate.is_symlink():
                    continue
                resolved = candidate.resolve()
                resolved.relative_to(root)
                if configured_is_file:
                    if resolved != configured:
                        continue
                else:
                    resolved.relative_to(configured)
                size = resolved.stat().st_size
            except (OSError, ValueError):
                continue
            if (
                not resolved.is_file()
                or resolved in seen
                or resolved.suffix.lower() not in TEXT_SUFFIXES
                or size > MAX_FILE_BYTES
            ):
                continue
            seen.add(resolved)
            yield resolved


def _query_terms(query: str) -> list[str]:
    terms = [
        term.casefold()
        for term in re.findall(r"[\w.-]+", query, flags=re.UNICODE)
        if len(term) > 1
    ]
    return list(dict.fromkeys(terms)) or [query.casefold()]


def _match_file(path: Path, query: str, terms: list[str]) -> Optional[tuple[int, str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    folded = text.casefold()
    phrase = query.casefold().strip()
    score = len(terms) + 2 if phrase and phrase in folded else sum(term in folded for term in terms)
    if score == 0:
        return None
    for line in text.splitlines():
        candidate = line.strip()
        folded_line = candidate.casefold()
        if candidate and (phrase in folded_line or any(term in folded_line for term in terms)):
            return score, candidate[:240]
    return score, ""


def _layered_recall(
    query: str,
    *,
    mode: str,
    codex_home: Path,
    strategy: str,
    limit: int,
) -> dict[str, Any]:
    root = codex_home.expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Codex home is not a directory")
    terms = _query_terms(query)
    checked_layers: list[str] = []
    matches: list[dict[str, object]] = []
    scanned_files = 0
    scanned_bytes = 0
    truncated = False
    search_all = strategy == "all" or mode in {"recent", "evidence"}
    for layer, paths in _configured_layers(root, mode):
        checked_layers.append(layer)
        layer_matches: list[tuple[int, Path, str]] = []
        for path in _iter_files(paths, root):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if scanned_files >= MAX_RECALL_FILES or scanned_bytes + size > MAX_RECALL_BYTES:
                truncated = True
                break
            scanned_files += 1
            scanned_bytes += size
            matched = _match_file(path, query, terms)
            if matched:
                score, snippet = matched
                layer_matches.append((score, path, snippet))
        layer_matches.sort(key=lambda item: (-item[0], str(item[1])))
        for score, path, snippet in layer_matches[: limit - len(matches)]:
            matches.append(
                {
                    "layer": layer,
                    "file": path.relative_to(root).as_posix(),
                    "snippet": snippet,
                    "score": score,
                }
            )
        if (matches and not search_all) or len(matches) >= limit:
            break
        if truncated:
            break
    return {
        "schema_version": 1,
        "mode": mode,
        "strategy": strategy,
        "authority": "working_tree_layer",
        "committed": False,
        "status": "hit" if matches else "miss",
        "checked_layers": checked_layers,
        "matches": matches,
        "summary": f"Found {len(matches)} hit(s) for {mode} recall.",
        "should_drill_deeper": not matches,
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "truncated": truncated,
    }


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_GRAPH_BYTES:
            raise ValueError("graph artifact exceeds size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("graph artifact is unreadable") from exc
    if not isinstance(value, dict):
        raise ValueError("graph artifact must be an object")
    return value


def _normalized_phrase(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold()).strip()


def _phrase_matches(query: str, phrase: str) -> bool:
    normalized = _normalized_phrase(phrase)
    if not normalized:
        return False
    if re.fullmatch(r"[a-z0-9_+#. -]+", normalized):
        return bool(re.search(rf"(?<![a-z0-9_]){re.escape(normalized)}(?![a-z0-9_])", query))
    return normalized in query


def _graph_result(profile: AccessProfile, **result: Any) -> dict[str, Any]:
    if profile.graph_context_discovery:
        result.setdefault("candidates", [])
    return result


def _graph_artifacts(
    graph_dir: Path,
    *,
    graph_id: str,
    source_commit: object,
    profile: AccessProfile,
) -> tuple[dict[str, Any], dict[str, Any]] | dict[str, Any]:
    health_path = graph_dir / "health.json"
    extraction_path = graph_dir / "source_extraction.json"
    if not health_path.is_file() or not extraction_path.is_file():
        return _graph_result(
            profile,
            status="unavailable",
            reason="graph_artifact_missing",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    try:
        health = _read_json(health_path)
        extraction = _read_json(extraction_path)
    except ValueError:
        return _graph_result(
            profile,
            status="unavailable",
            reason="graph_artifact_invalid",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    if profile.graph_context_discovery and (
        health.get("graph_id") != graph_id or extraction.get("graph_id") != graph_id
    ):
        return _graph_result(
            profile,
            status="unavailable",
            reason="graph_identity_mismatch",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    if health.get("source_revision") != source_commit:
        return _graph_result(
            profile,
            status="stale",
            reason="source_revision_mismatch",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    if health.get("source_dirty") is not False:
        return _graph_result(
            profile,
            status="stale",
            reason="source_worktree_dirty",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    hard_gates = health.get("hard_gates")
    if not isinstance(hard_gates, dict) or not hard_gates or not all(hard_gates.values()):
        return _graph_result(
            profile,
            status="unavailable",
            reason="graph_hard_gate_failed",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    if profile.graph_context_discovery:
        fingerprint = hashlib.sha256(
            json.dumps(extraction, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if health.get("source_fingerprint") != fingerprint:
            return _graph_result(
                profile,
                status="unavailable",
                reason="graph_fingerprint_mismatch",
                graph_id=graph_id,
                advisory_only=True,
                neighbors=[],
            )
    return health, extraction


def _rank_graph_contexts(query: str, extraction: dict[str, Any], *, limit: int) -> list[dict[str, Any]]:
    normalized_query = _normalized_phrase(query)
    query_terms = set(re.findall(r"[a-z0-9_+#.-]{3,}", normalized_query))
    candidates: list[dict[str, Any]] = []
    for node in extraction.get("nodes", []):
        if (
            not isinstance(node, dict)
            or node.get("kind") != "context"
            or node.get("status", "active") != "active"
            or not isinstance(node.get("id"), str)
        ):
            continue
        suppressions = [
            value
            for field in ("non_triggers", "suppress_phrases")
            for value in node.get(field, [])
            if isinstance(value, str) and _phrase_matches(normalized_query, value)
        ]
        if suppressions:
            continue
        score = 0.0
        matched: list[str] = []
        for field, weight in (("triggers", 12.0), ("routing_terms", 7.0)):
            values = node.get(field, [])
            if not isinstance(values, list):
                continue
            hits = [value for value in values if isinstance(value, str) and _phrase_matches(normalized_query, value)]
            if hits:
                score += weight * len(hits)
                matched.extend(f"{field}:{value}" for value in hits[:3])
        summary = node.get("summary", "")
        if isinstance(summary, str):
            summary_terms = set(re.findall(r"[a-z0-9_+#.-]{3,}", summary.casefold()))
            overlap = sorted(query_terms & summary_terms)
            if overlap:
                score += 2.0 * len(overlap)
                matched.append("summary:" + ", ".join(overlap[:4]))
        if score < MIN_GRAPH_CANDIDATE_SCORE:
            continue
        context_id = node["id"].removeprefix("context_")
        entry_path = node.get("entry_path")
        if not isinstance(entry_path, str):
            continue
        candidates.append(
            {
                "context_id": context_id,
                "entry_path": entry_path,
                "summary": summary,
                "score": round(score, 4),
                "matched": matched,
                "source_file": node.get("source_file"),
                "source_location": node.get("source_location"),
            }
        )
    candidates.sort(key=lambda item: (-item["score"], item["context_id"]))
    if len(candidates) > 1 and candidates[0]["score"] == candidates[1]["score"]:
        return []
    return candidates[:limit]


def _graph_candidates(
    route: dict[str, Any],
    *,
    query: str,
    graph_root: Path,
    limit: int,
    profile: AccessProfile,
) -> dict[str, Any]:
    if route.get("trace", {}).get("stage") == "privacy_boundary":
        return _graph_result(
            profile,
            status="skipped",
            reason="privacy_boundary",
            advisory_only=True,
            neighbors=[],
        )
    collection_id = route.get("collection_id")
    context_id = route.get("context_id")
    if profile.graph_context_discovery and route.get("decision") == "ambiguous":
        return _graph_result(
            profile,
            status="skipped",
            reason="authoritative_route_ambiguous",
            advisory_only=True,
            neighbors=[],
        )
    graph_id = GRAPH_BY_COLLECTION.get(collection_id)
    if (
        profile.graph_context_discovery
        and graph_id is None
        and route.get("trace", {}).get("stage") == "collection_selection"
    ):
        graph_id = GRAPH_BY_COLLECTION["work"]
    if graph_id is None or (
        not profile.graph_context_discovery and not isinstance(context_id, str)
    ):
        return _graph_result(
            profile,
            status="not_applicable",
            reason="route_has_no_context_graph",
            advisory_only=True,
            neighbors=[],
        )
    graph_dir = graph_root.expanduser().resolve() / graph_id / "graphify-out"
    source_commit = route.get("trace", {}).get("source_commit")
    artifacts = _graph_artifacts(
        graph_dir,
        graph_id=graph_id,
        source_commit=source_commit,
        profile=profile,
    )
    if isinstance(artifacts, dict):
        return artifacts
    _, extraction = artifacts
    if profile.graph_context_discovery and not isinstance(context_id, str):
        candidates = _rank_graph_contexts(query, extraction, limit=limit)
        return _graph_result(
            profile,
            status="candidate" if candidates else "miss",
            reason=(
                "bounded_revision_matched_context_discovery"
                if candidates
                else "no_bounded_context_candidate"
            ),
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
            candidates=candidates,
        )
    nodes = {
        node.get("id"): node
        for node in extraction.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    routed_node = f"context_{context_id}"
    if routed_node not in nodes:
        return _graph_result(
            profile,
            status="unavailable",
            reason="routed_node_missing",
            graph_id=graph_id,
            advisory_only=True,
            neighbors=[],
        )
    neighbors: list[dict[str, Any]] = []
    for edge in extraction.get("edges", []):
        if not isinstance(edge, dict) or edge.get("confidence") != "EXTRACTED":
            continue
        direction: Optional[str] = None
        other_id: Optional[str] = None
        if edge.get("source") == routed_node:
            direction, other_id = "outgoing", edge.get("target")
        elif edge.get("target") == routed_node:
            direction, other_id = "incoming", edge.get("source")
        if direction is None or not isinstance(other_id, str) or other_id not in nodes:
            continue
        other = nodes[other_id]
        neighbors.append(
            {
                "direction": direction,
                "relation": edge.get("relation"),
                "node_id": other_id,
                "label": other.get("label"),
                "kind": other.get("kind"),
                "source_file": edge.get("source_file"),
                "source_location": edge.get("source_location"),
                "assertion_id": edge.get("id"),
            }
        )
    neighbors.sort(
        key=lambda item: (
            item["direction"],
            str(item["relation"]),
            item["node_id"],
            str(item["assertion_id"]),
        )
    )
    return _graph_result(
        profile,
        status="used",
        reason="revision_matched_explicit_assertions",
        graph_id=graph_id,
        routed_node=routed_node,
        advisory_only=True,
        neighbors=neighbors[:limit],
    )


def _legacy_durable_access(
    query: str,
    *,
    root: Path,
    router_root: Path,
    limit: int,
    projection_path: Path,
    hybrid_projection_path: Path,
    recall_policy: Any,
    embedding_helper: Path,
    embedding_cache: Path,
    route: Callable[..., dict[str, Any]],
    verify_recall_request: Callable[..., Any],
) -> dict[str, Any]:
    try:
        privacy_route = route(query, root=router_root, read_selector=None)
        request = verify_recall_request(
            query,
            recall_policy,
            route_result=privacy_route,
            entry_point="durable_access",
            session_id="durable-access:"
            + hashlib.sha256(
                (
                    str(root.resolve(strict=False))
                    + "\0"
                    + str(router_root.resolve(strict=False))
                ).encode("utf-8")
            ).hexdigest(),
        )
    except Exception:
        return {
            "schema_version": 1,
            "mode": "durable",
            "authority": "none",
            "privacy_stage": "classification_failed",
            "projection": {
                "schema_version": 1,
                "status": "abstain",
                "reason": "query_classification_failed",
                "matches": [],
            },
        }
    privacy_stop = privacy_route.get("trace", {}).get("stage") == "privacy_boundary"
    from agent_memory_system.embedding import LocalNaturalLanguageEmbedding
    from agent_memory_system.retrieval import GovernedHybridRetrieval
    from memory_control_plane.projection import MemoryProjection, ProjectionError

    projection = MemoryProjection(
        repository=root,
        index_path=projection_path,
        authority_roots=("core", "platform", "learnings"),
    )
    typed_policy = request.policy
    if privacy_stop:
        result = projection.recall(
            query,
            context=typed_policy,
            limit=min(limit, 20),
        )
        return {
            "schema_version": 1,
            "mode": "durable",
            "authority": "exact_committed_memory_projection",
            "privacy_stage": privacy_route.get("trace", {}).get("stage"),
            "projection": result,
        }
    hybrid = GovernedHybridRetrieval(
        authority=projection,
        index_path=hybrid_projection_path,
        embedding=LocalNaturalLanguageEmbedding(
            helper_source=embedding_helper,
            cache_dir=embedding_cache,
        ),
    )
    try:
        result = hybrid.recall(
            query,
            context=typed_policy,
            limit=min(limit, 20),
            request_binding=request.to_mapping(),
        )
        authority = "governed_hybrid_committed_projection"
    except (RuntimeError, ProjectionError):
        try:
            result = projection.recall(
                query,
                context=typed_policy,
                limit=min(limit, 20),
            )
            authority = "exact_committed_memory_projection"
        except ProjectionError:
            result = {
                "schema_version": 1,
                "status": "unavailable",
                "reason": "projection_unavailable",
                "matches": [],
            }
            authority = "exact_committed_memory_projection"
    return {
        "schema_version": 1,
        "mode": "durable",
        "authority": authority,
        "privacy_stage": privacy_route.get("trace", {}).get("stage"),
        "projection": result,
    }


def _v2_durable_access(
    query: str,
    *,
    root: Path,
    limit: int,
    projection_path: Path,
    recall_scopes: tuple[str, ...],
    high_stakes: bool,
    route: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    privacy_route = route(query, root=root, read_selector=None)
    privacy_stop = privacy_route.get("trace", {}).get("stage") == "privacy_boundary"
    from memory_control_plane.projection import MemoryProjection, ProjectionError

    projection = MemoryProjection(
        repository=root,
        index_path=projection_path,
        authority_roots=("core", "platform", "learnings"),
    )
    try:
        result = projection.recall(
            query,
            context={
                "scopes": list(recall_scopes),
                "applies_to": "codex",
                "private_profile": privacy_stop,
                "high_stakes": high_stakes,
            },
            limit=min(limit, 20),
        )
    except ProjectionError:
        result = {
            "schema_version": 1,
            "status": "unavailable",
            "reason": "projection_unavailable",
            "matches": [],
        }
    return {
        "schema_version": 1,
        "mode": "durable",
        "authority": "exact_committed_memory_projection",
        "privacy_stage": privacy_route.get("trace", {}).get("stage"),
        "projection": result,
    }


def _access_knowledge(
    query: str,
    *,
    profile: AccessProfile,
    route: Callable[..., dict[str, Any]],
    live_recall: Callable[..., dict[str, Any]],
    mode: str,
    root: Path,
    router_root: Path | None,
    codex_home: Path,
    graph_root: Path,
    strategy: str,
    limit: int,
    read_selector: Optional[str],
    expand_graph: bool,
    projection_path: Path,
    hybrid_projection_path: Path | None,
    recall_policy: Any,
    recall_scopes: tuple[str, ...],
    high_stakes: bool,
    embedding_helper: Path | None,
    embedding_cache: Path | None,
    verify_recall_request: Callable[..., Any] | None,
) -> dict[str, Any]:
    """Read governed knowledge without letting candidate indexes become authority."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")
    if mode not in {"domain", "durable", "policy", "history", "recent", "evidence"}:
        raise ValueError("unsupported knowledge access mode")
    if strategy not in {"escalate", "all"}:
        raise ValueError("unsupported recall strategy")
    if limit < 1 or limit > 50:
        raise ValueError("limit must be between 1 and 50")
    trusted_router_root = root if router_root is None else router_root
    if mode == "durable":
        if profile.legacy_durable:
            if (
                hybrid_projection_path is None
                or embedding_helper is None
                or embedding_cache is None
                or verify_recall_request is None
            ):
                raise ValueError("legacy durable access dependencies are unavailable")
            return _legacy_durable_access(
                query,
                root=root,
                router_root=trusted_router_root,
                limit=limit,
                projection_path=projection_path,
                hybrid_projection_path=hybrid_projection_path,
                recall_policy=recall_policy,
                embedding_helper=embedding_helper,
                embedding_cache=embedding_cache,
                route=route,
                verify_recall_request=verify_recall_request,
            )
        return _v2_durable_access(
            query,
            root=root,
            limit=limit,
            projection_path=projection_path,
            recall_scopes=recall_scopes,
            high_stakes=high_stakes,
            route=route,
        )
    if mode in {"history", "recent", "evidence"}:
        return {
            "schema_version": 1,
            "mode": mode,
            "strategy": strategy,
            "authority": "privacy_boundary",
            "committed": False,
            "status": "abstain",
            "reason": "private_capability_required",
            "checked_layers": [],
            "matches": [],
            "summary": "Private-local recall is disabled until a trusted host capability exists.",
            "should_drill_deeper": False,
        }
    if mode != "domain":
        return _layered_recall(
            query,
            mode=mode,
            codex_home=codex_home,
            strategy=strategy,
            limit=limit,
        )

    route_result = route(
        query,
        root=trusted_router_root,
        read_selector=read_selector,
    )
    privacy_stop = route_result.get("trace", {}).get("stage") == "privacy_boundary"
    backend = route_result.get("trace", {}).get("retrieval_backend", "not_run")
    graph = (
        _graph_candidates(
            route_result,
            query=query,
            graph_root=graph_root,
            limit=limit,
            profile=profile,
        )
        if expand_graph
        else _graph_result(
            profile,
            status="skipped",
            reason="disabled_by_caller",
            advisory_only=True,
            neighbors=[],
        )
    )
    semantic = (
        live_recall(
            query,
            route=route_result,
            root=root,
            limit=min(limit, 5),
        )
        if profile.live_semantic_recall
        else {
            "status": "skipped" if privacy_stop else "unavailable",
            "backend": None,
            "reason": (
                "privacy_boundary" if privacy_stop else "no_configured_embedding_index"
            ),
            "candidate_only": True,
        }
    )
    return {
        "schema_version": 1,
        "mode": "domain",
        "authority": (
            "exact_committed_document"
            if route_result.get("document") is not None
            else "governed_route"
        ),
        "route": route_result,
        "retrieval": {
            "lexical": {
                "status": "skipped" if backend == "not_run" else "used",
                "backend": backend,
                "candidate_only": False,
            },
            "semantic": semantic,
            "graph": graph,
        },
    }


def access_knowledge(
    query: str,
    *,
    mode: str = "domain",
    root: Path = MEMORIES_ROOT,
    codex_home: Path = CODEX_HOME,
    graph_root: Path = GRAPH_ROOT,
    strategy: str = "escalate",
    limit: int = 10,
    read_selector: Optional[str] = "first",
    expand_graph: bool = True,
    projection_path: Path = MEMORY_PROJECTION,
    recall_scopes: tuple[str, ...] = ("global", "platform", "learning"),
    high_stakes: bool = False,
) -> dict[str, Any]:
    return _access_knowledge(
        query,
        profile=V2_ACCESS_PROFILE,
        route=route_knowledge,
        live_recall=governed_live_recall,
        mode=mode,
        root=root,
        router_root=None,
        codex_home=codex_home,
        graph_root=graph_root,
        strategy=strategy,
        limit=limit,
        read_selector=read_selector,
        expand_graph=expand_graph,
        projection_path=projection_path,
        hybrid_projection_path=None,
        recall_policy=None,
        recall_scopes=recall_scopes,
        high_stakes=high_stakes,
        embedding_helper=None,
        embedding_cache=None,
        verify_recall_request=None,
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
    parser.add_argument("--read", nargs="?", const="first", default="first")
    parser.add_argument("--no-graph", action="store_true")
    parser.add_argument("--high-stakes", action="store_true")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args()
    try:
        result = access_knowledge(
            " ".join(args.query),
            mode=args.mode,
            codex_home=args.codex_home,
            strategy=args.strategy,
            limit=args.limit,
            read_selector=args.read,
            expand_graph=not args.no_graph,
            high_stakes=args.high_stakes,
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
