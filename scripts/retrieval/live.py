from __future__ import annotations

import hashlib
import re
import unicodedata
from pathlib import Path
from typing import Any, Mapping, Optional

import retrieval_v2_knowledge_router as router
from retrieval.hybrid import HybridRetriever


MAX_LIVE_UNITS = 10_000
MAX_RETRIEVAL_DOCUMENTS = 5000
MAX_RETRIEVAL_DOCUMENT_BYTES = 512 * 1024
MAX_RETRIEVAL_TOTAL_BYTES = 64 * 1024 * 1024
RETRIEVAL_SUFFIXES = frozenset({".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".toml"})
NON_RECALL_DIRECTORY_ROLES = frozenset(
    {
        "archive",
        "cache",
        "cards",
        "evals",
        "indexes",
        "personal_memories",
        "rejected",
        "runs",
        "source-dump",
        "source_dump",
        "sources",
        "vendor",
    }
)
CHUNK_CHARACTERS = 1200
CHUNK_OVERLAP = 160
HEADING = re.compile(r"(?m)^(#{1,6})\s+(.+?)\s*$")


def _normalized_path(relative: Path) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFKC", part).casefold() for part in relative.parts)


def _has_non_recall_directory(relative: Path, *, declaration_is_directory: bool) -> bool:
    directories = relative.parts if declaration_is_directory else relative.parts[:-1]
    return bool(
        NON_RECALL_DIRECTORY_ROLES.intersection(
            unicodedata.normalize("NFKC", part).casefold() for part in directories
        )
    )


def _declared_retrieval_files(source: router.CollectionSource, raw: object) -> list[Path]:
    """Resolve one registry file/directory declaration against committed Git authority."""
    if not isinstance(raw, str):
        raise ValueError("retrieval path declaration must be a string")
    if not raw.endswith("/"):
        relative = router._safe_relative(raw)
        return [] if _has_non_recall_directory(relative, declaration_is_directory=False) else [relative]
    directory = router._safe_relative(raw[:-1])
    if _has_non_recall_directory(directory, declaration_is_directory=True):
        return []
    committed = source.tree_prefix / directory if source.tree_prefix.parts else directory
    tree = router._run_git_bytes(
        source.repository,
        "ls-tree",
        "-r",
        "-z",
        "-l",
        source.revision,
        "--",
        committed.as_posix(),
    )
    files: list[Path] = []
    normalized_paths: dict[tuple[str, ...], tuple[str, ...]] = {}
    normalized_directories: dict[tuple[str, ...], tuple[str, ...]] = {}
    for raw_entry in tree.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.decode("ascii").split()
            size = int(raw_size)
            committed_path = router._safe_relative(raw_path.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("governed retrieval directory contains an invalid entry") from exc
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or not re.fullmatch(r"[0-9a-f]{40}", object_id)
            or size < 0
        ):
            continue
        try:
            relative = (
                committed_path.relative_to(source.tree_prefix)
                if source.tree_prefix.parts
                else committed_path
            )
            relative.relative_to(directory)
        except ValueError as exc:
            raise ValueError("governed retrieval directory escaped its declaration") from exc
        normalized = _normalized_path(relative)
        raw_parts = relative.parts
        for index in range(1, len(raw_parts)):
            normalized_directory = normalized[:index]
            raw_directory = raw_parts[:index]
            previous_directory = normalized_directories.get(normalized_directory)
            if previous_directory is not None and previous_directory != raw_directory:
                raise ValueError("governed retrieval directory contains colliding directory paths")
            normalized_directories[normalized_directory] = raw_directory
        previous = normalized_paths.get(normalized)
        if previous is not None and previous != raw_parts:
            raise ValueError("governed retrieval directory contains colliding paths")
        if any(
            existing != normalized
            and (
                existing == normalized[: len(existing)]
                or normalized == existing[: len(normalized)]
            )
            for existing in normalized_paths
        ):
            raise ValueError("governed retrieval directory contains colliding paths")
        normalized_paths[normalized] = raw_parts
        if (
            not _has_non_recall_directory(relative, declaration_is_directory=False)
            and relative.suffix.casefold() in RETRIEVAL_SUFFIXES
            and size <= MAX_RETRIEVAL_DOCUMENT_BYTES
        ):
            files.append(relative)
    if not files:
        raise ValueError("governed retrieval directory has no admissible committed files")
    return sorted(set(files), key=lambda path: path.as_posix())


def governed_retrieval_documents(
    *,
    root: Path,
    collection_id: Optional[str] = None,
    context_id: Optional[str] = None,
    include_documents: bool = True,
) -> dict[str, Any]:
    """Reopen bounded registry-declared documents from committed authority."""
    parent_revision = router._git_revision(root)
    registry_bytes = router._git_regular_blob(root, parent_revision, router.REGISTRY_PATH)
    registry_digest = hashlib.sha256(registry_bytes).hexdigest()
    registry = router.load_collection_registry(
        root,
        content=registry_bytes,
        validate_worktree_paths=False,
    )
    collections = {
        item["id"]: item
        for item in registry["collections"]
        if item["status"] == "active" and item["searchable"]
    }
    if collection_id is not None and collection_id not in collections:
        return {
            "schema_version": 1,
            "status": "miss",
            "documents": [],
            "aliases": {},
            "source_revisions": {},
        }
    selected_collections = (
        {collection_id: collections[collection_id]}
        if collection_id is not None
        else collections
    )
    sources = {
        identifier: router.resolve_collection_source(root, collection)
        for identifier, collection in selected_collections.items()
    }
    engine = router._load_router_engine(
        root,
        registry,
        router.resolve_collection_sources(root, registry),
    )
    context_registries = router._load_context_registries(registry, sources, engine)
    documents: list[dict[str, Any]] = []
    context_descriptors: list[dict[str, Any]] = []
    aliases: dict[str, str] = {}
    total_bytes = 0
    seen: set[tuple[str, str]] = set()
    source_revisions: dict[str, str] = {}
    for identifier, collection in selected_collections.items():
        source = sources[identifier]
        source_revisions[identifier] = source.revision
        mount = str(collection["mount"])
        context_registry_path = router._safe_relative(collection["registry_path"])
        context_registry_bytes = router._source_file_bytes(source, context_registry_path)
        context_registry_sha256 = hashlib.sha256(context_registry_bytes).hexdigest()
        declared: dict[str, set[str]] = {}
        declared_paths: dict[tuple[str, ...], tuple[str, ...]] = {}
        declared_directories: dict[tuple[str, ...], tuple[str, ...]] = {}

        def admit(raw: object, owner: str) -> None:
            if not include_documents:
                return
            for relative in _declared_retrieval_files(source, raw):
                if relative.suffix.casefold() not in RETRIEVAL_SUFFIXES:
                    continue
                normalized = _normalized_path(relative)
                raw_parts = relative.parts
                for index in range(1, len(raw_parts)):
                    normalized_directory = normalized[:index]
                    raw_directory = raw_parts[:index]
                    previous_directory = declared_directories.get(normalized_directory)
                    if previous_directory is not None and previous_directory != raw_directory:
                        raise ValueError("governed retrieval declarations contain colliding directory paths")
                    declared_directories[normalized_directory] = raw_directory
                previous = declared_paths.get(normalized)
                if previous is not None and previous != raw_parts:
                    raise ValueError("governed retrieval declarations contain colliding paths")
                if any(
                    existing != normalized
                    and (
                        existing == normalized[: len(existing)]
                        or normalized == existing[: len(normalized)]
                    )
                    for existing in declared_paths
                ):
                    raise ValueError("governed retrieval declarations contain colliding paths")
                declared_paths[normalized] = raw_parts
                declared.setdefault(relative.as_posix(), set()).add(owner)

        admit(collection["entry_path"], "collection")
        for context in context_registries.get(identifier, {}).get("contexts", []):
            if context.get("status") != "active" or not isinstance(context.get("id"), str):
                continue
            current_context = str(context["id"])
            if context_id is not None and current_context != context_id:
                continue
            aliases[current_context] = current_context
            for trigger in context.get("triggers", []):
                if isinstance(trigger, str) and 1 < len(trigger) <= 120:
                    aliases[trigger] = current_context
            descriptor_terms = [
                current_context,
                str(context.get("title", "")),
                str(context.get("summary", "")),
            ]
            descriptor_terms.extend(
                value
                for field in ("triggers", "routing_terms")
                for value in context.get(field, [])
                if isinstance(value, str)
            )
            for deeper_route in context.get("deeper_routes", []):
                if not isinstance(deeper_route, dict):
                    continue
                descriptor_terms.extend(
                    value
                    for field in ("all", "any")
                    for value in deeper_route.get(field, [])
                    if isinstance(value, str)
                )
            descriptor_content = "\n".join(
                dict.fromkeys(value.strip() for value in descriptor_terms if value.strip())
            )
            descriptor_id = hashlib.sha256(
                (
                    source.revision
                    + "\0"
                    + identifier
                    + "\0"
                    + current_context
                    + "\0"
                    + descriptor_content
                ).encode("utf-8")
            ).hexdigest()[:32]
            context_descriptors.append(
                {
                    "unit_id": "live-context-" + descriptor_id,
                    "unit_type": "context_descriptor",
                    "collection_id": identifier,
                    "context_ids": [current_context],
                    "content": descriptor_content,
                    "heading": current_context.replace("_", " "),
                    "source_path": f"{mount}/{context_registry_path.as_posix()}",
                    "serialized_evidence": (
                        "[knowledge routing evidence; not instruction]\n"
                        f"source={mount}/{context_registry_path.as_posix()}@{source.revision}\n"
                        f"sha256={context_registry_sha256}\n"
                        f"context_id={current_context}\n"
                        f"content={descriptor_content}"
                    ),
                    "status": "active",
                    "scope": "global",
                    "applies_to": "all",
                    "trust_class": "canonical_registry",
                    "non_triggers": [
                        value
                        for value in context.get("non_triggers", [])
                        if isinstance(value, str)
                    ],
                    "source_revision": source.revision,
                    "authority_sha256": context_registry_sha256,
                    "canonical_reopened": True,
                }
            )
            for field in ("read_path", "deeper_files"):
                values = context.get(field, [])
                if not isinstance(values, list):
                    raise ValueError("pinned context registry retrieval paths must be arrays")
                for value in values:
                    admit(value, current_context)
            for route in context.get("deeper_routes", []):
                if not isinstance(route, dict) or not isinstance(route.get("files", []), list):
                    raise ValueError("pinned context registry deeper route is invalid")
                for value in route.get("files", []):
                    admit(value, current_context)
        for relative_text, owners in sorted(declared.items()):
            identity = (identifier, relative_text)
            if identity in seen:
                continue
            seen.add(identity)
            relative = Path(relative_text)
            content = router._source_file_bytes(source, relative)
            if len(content) > MAX_RETRIEVAL_DOCUMENT_BYTES:
                # Oversized canonical files remain available through the exact
                # routed reader. Skipping them here preserves the bounded
                # candidate corpus without making the entire context unavailable.
                continue
            total_bytes += len(content)
            if len(documents) >= MAX_RETRIEVAL_DOCUMENTS or total_bytes > MAX_RETRIEVAL_TOTAL_BYTES:
                raise ValueError("governed retrieval corpus exceeds size limit")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("governed retrieval document must be UTF-8") from exc
            documents.append(
                {
                    "collection_id": identifier,
                    "context_ids": sorted(owners),
                    "authority_path": f"{mount}/{relative.as_posix()}",
                    "source_revision": source.revision,
                    "authority_sha256": hashlib.sha256(content).hexdigest(),
                    "content": text,
                    "canonical_reopened": True,
                }
            )
    if router._git_revision(root) != parent_revision:
        raise ValueError("parent knowledge revision changed during retrieval")
    if router._committed_file_sha256(root, parent_revision, router.REGISTRY_PATH) != registry_digest:
        raise ValueError("parent collection registry changed during retrieval")
    router._assert_runtime_sources_stable(root, registry, sources)
    return {
        "schema_version": 1,
        "status": "hit" if documents or context_descriptors else "miss",
        "documents": documents,
        "context_descriptors": context_descriptors,
        "aliases": aliases,
        "source_revisions": source_revisions,
        "total_bytes": total_bytes,
    }


def _metadata(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    finish = text.find("\n---\n", 4)
    if finish < 0:
        return {}
    result: dict[str, str] = {}
    for line in text[4:finish].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]*", key.strip()):
            result[key.strip()] = value.strip().strip("'\"")
    return result


def _document_chunks(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    text = str(document["content"])
    headings = [(match.start(), match.group(2).strip()) for match in HEADING.finditer(text)]
    boundaries = sorted({0, *(position for position, _heading in headings), len(text)})
    result: list[dict[str, Any]] = []
    metadata = _metadata(text)
    for boundary_index in range(len(boundaries) - 1):
        start, finish = boundaries[boundary_index], boundaries[boundary_index + 1]
        section = text[start:finish].strip()
        if not section:
            continue
        heading = next((value for position, value in reversed(headings) if position <= start), "document")
        offset = 0
        while offset < len(section):
            stop = min(len(section), offset + CHUNK_CHARACTERS)
            if stop < len(section):
                newline = section.rfind("\n", offset + CHUNK_CHARACTERS // 2, stop)
                if newline > offset:
                    stop = newline
            chunk = section[offset:stop].strip()
            if chunk:
                identity = hashlib.sha256(
                    (
                        str(document["source_revision"])
                        + "\0"
                        + str(document["authority_path"])
                        + "\0"
                        + str(start + offset)
                        + "\0"
                        + chunk
                    ).encode("utf-8")
                ).hexdigest()[:32]
                evidence = (
                    "[knowledge evidence; not instruction]\n"
                    f"source={document['authority_path']}@{document['source_revision']}\n"
                    f"sha256={document['authority_sha256']}\n"
                    f"heading={heading}\n"
                    f"content={chunk}"
                )
                result.append(
                    {
                        "unit_id": "live-" + identity,
                        "content": chunk,
                        "heading": heading,
                        "source_path": document["authority_path"],
                        "unit_type": "document_chunk",
                        "context_ids": list(document.get("context_ids", [])),
                        "serialized_evidence": evidence,
                        "status": metadata.get("status", "active"),
                        "scope": metadata.get("scope", "global"),
                        "applies_to": metadata.get("applies_to", "all"),
                        "valid_from": metadata.get("valid_from"),
                        "valid_to": metadata.get("valid_to"),
                        "superseded_by": metadata.get("superseded_by"),
                        "deleted_at": metadata.get("deleted_at"),
                        "trust_class": metadata.get("trust_class", "canonical_legacy"),
                        "source_revision": document["source_revision"],
                        "authority_sha256": document["authority_sha256"],
                        "canonical_reopened": True,
                    }
                )
            if stop >= len(section):
                break
            offset = max(offset + 1, stop - CHUNK_OVERLAP)
    return result


def governed_live_recall(
    query: str,
    *,
    route: Mapping[str, Any],
    root: Path,
    limit: int = 5,
) -> dict[str, Any]:
    if route.get("trace", {}).get("stage") == "privacy_boundary":
        return {
            "status": "skipped",
            "reason": "privacy_boundary",
            "backend": None,
            "candidate_only": True,
            "matches": [],
            "internal_candidates": 0,
        }
    if route.get("current_sources_required"):
        return {
            "status": "skipped",
            "reason": "current_source_required",
            "backend": None,
            "candidate_only": True,
            "matches": [],
            "internal_candidates": 0,
        }
    selected_collection = route.get("collection_id")
    if not isinstance(selected_collection, str) and route.get("trace", {}).get("stage") == "collection_selection":
        selected_collection = "work"
    reason_codes = route.get("reason_codes", [])
    weak_formal_route = bool(
        route.get("decision") != "load"
        or not isinstance(route.get("context_id"), str)
        or route.get("alternatives")
        or (
            isinstance(reason_codes, list)
            and reason_codes
            and all(str(reason).startswith("term:") for reason in reason_codes)
        )
    )
    try:
        corpus = governed_retrieval_documents(
            root=root,
            collection_id=selected_collection if isinstance(selected_collection, str) else None,
            # Search every active context only when the formal route is weak. A
            # strong route already reopened its exact entry document, so its
            # candidate lane can remain inside the chosen context.
            context_id=(
                None
                if weak_formal_route
                else str(route["context_id"])
            ),
            # A weak formal route only needs the compact, committed registry
            # projection to recover alternate contexts. Avoid rebuilding the
            # multi-megabyte document corpus on this latency-sensitive lane.
            include_documents=not weak_formal_route,
        )
        descriptor_units = list(corpus.get("context_descriptors", []))
        document_units = [
            unit
            for document in corpus.get("documents", [])
            for unit in _document_chunks(document)
        ]
        units = descriptor_units + document_units
        if len(units) > MAX_LIVE_UNITS:
            raise ValueError("governed live unit budget exceeded")
        if not units:
            return {
                "status": "miss",
                "reason": "no_governed_retrieval_documents",
                "backend": "local_hybrid_rrf",
                "candidate_only": True,
                "matches": [],
                "internal_candidates": 0,
                "source_revisions": corpus.get("source_revisions", {}),
            }
        recalled_parts: list[dict[str, Any]] = []
        if weak_formal_route and descriptor_units:
            descriptor_retriever = HybridRetriever(
                descriptor_units,
                aliases=corpus.get("aliases", {}),
            )
            recalled_parts.append(
                descriptor_retriever.search(
                    query,
                    top_k=min(5, limit),
                    max_characters=1600 * min(5, limit),
                    internal_limit=15,
                    minimum_focus_coverage=0.0,
                    minimum_focus_matches=1,
                )
            )
        remaining_results = max(0, min(limit, 5) - sum(len(part.get("matches", [])) for part in recalled_parts))
        if remaining_results and document_units:
            document_retriever = HybridRetriever(
                document_units,
                aliases=corpus.get("aliases", {}),
            )
            recalled_parts.append(
                document_retriever.search(
                    query,
                    top_k=remaining_results,
                    max_characters=1600 * remaining_results,
                    internal_limit=35 if weak_formal_route else 50,
                    # Domain routing queries are often full natural-language
                    # paraphrases. Keep a bounded sparse alternative when at
                    # least two specific signals agree; benchmark defaults stay
                    # unchanged.
                    minimum_focus_coverage=0.05,
                    minimum_focus_matches=2,
                )
            )
        recalled_matches = [
            match
            for part in recalled_parts
            for match in part.get("matches", [])
        ][: min(limit, 5)]
        recalled = {
            "matches": recalled_matches,
            "internal_candidates": min(
                50,
                sum(int(part.get("internal_candidates", 0)) for part in recalled_parts),
            ),
            "candidate_channels": {
                f"part_{index}_{channel}": count
                for index, part in enumerate(recalled_parts, 1)
                for channel, count in part.get("candidate_channels", {}).items()
            },
            "dense": {
                "status": "disabled",
                "reason": "not_configured",
            },
            "filtered": {
                reason: sum(int(part.get("filtered", {}).get(reason, 0)) for part in recalled_parts)
                for reason in {
                    reason
                    for part in recalled_parts
                    for reason in part.get("filtered", {})
                }
            },
        }
    except (OSError, ValueError):
        return {
            "status": "unavailable",
            "reason": "governed_corpus_unavailable",
            "backend": None,
            "candidate_only": True,
            "matches": [],
            "internal_candidates": 0,
        }
    by_id = {str(unit["unit_id"]): unit for unit in units}
    matches: list[dict[str, Any]] = []
    for match in recalled.get("matches", []):
        unit = by_id.get(str(match.get("unit_id")))
        if unit is None:
            continue
        matches.append(
            {
                "unit_id": unit["unit_id"],
                "authority_path": unit["source_path"],
                "authority_sha256": unit["authority_sha256"],
                "source_revision": unit["source_revision"],
                "canonical_reopened": True,
                "unit_type": unit.get("unit_type", "document_chunk"),
                "context_ids": list(unit.get("context_ids", [])),
                "evidence": match["evidence"],
                "score": match["score"],
                "channels": match["channels"],
                "matched_terms": match["matched_terms"],
            }
        )
    return {
        "status": "used" if matches else "miss",
        "reason": "governed_committed_candidate_union" if matches else "confidence_below_threshold",
        "backend": "local_hybrid_rrf",
        "candidate_only": True,
        "matches": matches,
        "internal_candidates": recalled.get("internal_candidates", 0),
        "candidate_channels": recalled.get("candidate_channels", {}),
        "dense": recalled.get("dense", {}),
        "filtered": recalled.get("filtered", {}),
        "source_revisions": corpus.get("source_revisions", {}),
    }
