from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Protocol, Sequence

from retrieval.query import (
    detect_context_concepts,
    detect_multihop_relation_intent,
    detect_temporal_mode,
    english_lexical_variants,
    normalize_query_text,
)


TOP_K = 5
MAX_TOTAL_CHARACTERS = 8000
MAX_HIT_CHARACTERS = 1600
MAX_INTERNAL_CANDIDATES = 50
MAX_CONCEPT_CLUSTER_SIZE = 8
NORMALIZATION_VERSION = "nfkc-cjk-bigram-concepts-inflection-oov-v4"
RRF_K = 60.0
RETRIEVAL_CHANNELS = frozenset(
    {
        "identifier",
        "relation",
        "phrase",
        "alias",
        "concept",
        "lifecycle",
        "temporal",
        "path",
        "sparse",
        "dense",
    }
)

ASCII_TOKEN = re.compile(r"[a-z0-9][a-z0-9_+.#:@/-]*", re.IGNORECASE)
PATH_TOKEN = re.compile(r"[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+", re.IGNORECASE)
IDENTIFIER = re.compile(
    r"(?<![a-z0-9])(?:[a-z][a-z0-9]*[-_:./#][a-z0-9][a-z0-9._:/#-]*|[a-z]*\d[a-z0-9._:/#-]*)",
    re.IGNORECASE,
)
CJK_RUN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")
ASCII_ENTITY_PHRASE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Z][A-Za-z0-9_-]+)(?:\s+[A-Z][A-Za-z0-9_-]+){1,3}(?![A-Za-z0-9_])"
)

# These are stable vocabulary aliases, not query rewrites.  They make governed
# context names and common document roles addressable in either task language.
DEFAULT_ALIASES: Mapping[str, str] = {
    "mcp": "mcp",
    "temporal": "temporal",
    "模型上下文协议": "mcp",
    "model context protocol": "mcp",
    "提示与上下文工程": "prompt_engineering",
    "prompt engineering": "prompt_engineering",
    "技能工程": "skill_engineering",
    "skill engineering": "skill_engineering",
    "后端检索信息流": "backend_retrieval_information_flow",
    "backend retrieval information flow": "backend_retrieval_information_flow",
    "后端系统工程": "backend_systems_engineering",
    "backend systems engineering": "backend_systems_engineering",
    "智能体长期记忆知识库": "agent_memory_knowledge_bases",
    "agent memory knowledge bases": "agent_memory_knowledge_bases",
    "智能体循环与执行框架": "loop_harness_engineering",
    "loop harness engineering": "loop_harness_engineering",
    "开源工程模式": "github_engineering_patterns",
    "github engineering patterns": "github_engineering_patterns",
    "产品交付工程": "product_delivery_engineering",
    "product delivery engineering": "product_delivery_engineering",
    "创作者内容系统": "creator_content_systems",
    "creator content systems": "creator_content_systems",
    "视频内容生产": "video_content_production",
    "video content production": "video_content_production",
    "时间版本记忆": "temporal",
    "temporal memory": "temporal",
    "可复用模式": "patterns",
    "具体正文": "document",
    "原则": "principles",
    "架构": "architecture",
    "索引": "index",
    "检索规则": "retrieval",
    "待确认问题": "open_questions",
    "来源综合": "source_synthesis",
}

QUERY_NOISE = frozenset(
    {
        "a",
        "an",
        "and",
        "for",
        "from",
        "in",
        "of",
        "please",
        "retrieve",
        "source",
        "that",
        "the",
        "who",
        "with",
        "durable",
        "evidence",
        "memory",
        "请",
        "关于",
        "找回",
        "权威",
        "记忆",
        "证据",
        "保留",
    }
)
CONTEXT_CANONICALS = frozenset(
    {
        "mcp",
        "temporal",
        "prompt_engineering",
        "skill_engineering",
        "backend_retrieval_information_flow",
        "backend_systems_engineering",
        "agent_memory_knowledge_bases",
        "loop_harness_engineering",
        "github_engineering_patterns",
        "product_delivery_engineering",
        "creator_content_systems",
        "video_content_production",
    }
)


class DenseEncoder(Protocol):
    def encode(self, texts: list[str]) -> Iterable[Sequence[float]]:
        ...


def normalize_text(value: object) -> str:
    return normalize_query_text(value)


def tokenize(value: object) -> list[str]:
    normalized = normalize_text(value)
    result: list[str] = []
    result.extend(PATH_TOKEN.findall(normalized))
    for token in ASCII_TOKEN.findall(normalized):
        result.append(token)
        if any(separator in token for separator in ("_", "-", ".", "/", ":", "#", "@")):
            result.extend(part for part in re.split(r"[_\-./:#@]+", token) if len(part) > 1)
    for run in CJK_RUN.findall(normalized):
        if len(run) == 1:
            result.append(run)
        else:
            result.extend(run[index : index + 2] for index in range(len(run) - 1))
    return list(dict.fromkeys(token for token in result if token))


def extract_identifiers(value: object) -> list[str]:
    identifiers: list[str] = []
    for candidate in IDENTIFIER.findall(normalize_text(value)):
        letters = any(character.isalpha() for character in candidate)
        digits = any(character.isdigit() for character in candidate)
        structured = any(character in candidate for character in "-_:./#@")
        if len(candidate) >= 4 and ((letters and digits) or (digits and structured)):
            identifiers.append(candidate)
        elif len(candidate) >= 7 and re.fullmatch(r"[0-9a-f]+", candidate):
            identifiers.append(candidate)
    return list(dict.fromkeys(identifiers))


def extract_entities(value: object) -> list[str]:
    return list(
        dict.fromkeys(
            normalize_text(candidate)
            for candidate in ASCII_ENTITY_PHRASE.findall(str(value or ""))
            if 3 <= len(normalize_text(candidate)) <= 80
        )
    )


def _alias_is_explicitly_negated(normalized_query: str, alias: str) -> bool:
    normalized_alias = normalize_text(alias)
    if not normalized_alias or len(normalized_alias) > 80:
        return False
    escaped = re.escape(normalized_alias)
    if all(ord(character) < 128 for character in normalized_alias):
        boundary_alias = rf"(?<![a-z0-9_]){escaped}(?![a-z0-9_])"
    else:
        boundary_alias = escaped
    english = re.search(
        rf"\b(?:do\s+not|don't|never|avoid|exclude|without)\s+"
        rf"(?:(?:want|need|use|using|include|including|choose|select|adopt)\s+)?"
        rf"(?:the\s+)?{boundary_alias}",
        normalized_query,
    )
    english_no = re.search(rf"\bno\s+{boundary_alias}", normalized_query)
    english_copular = re.search(
        rf"{boundary_alias}\s+(?:is|are)\s+(?:not|never)\s+"
        rf"(?:required|needed|wanted|used|allowed|selected|adopted)\b",
        normalized_query,
    )
    chinese = re.search(
        rf"(?<![要用需])(?:不要|不用|不使用|无需|不需要|别用|禁止使用)"
        rf"[^，。,.!?；;]{{0,4}}{boundary_alias}",
        normalized_query,
    )
    return (
        english is not None
        or english_no is not None
        or english_copular is not None
        or chinese is not None
    )


def _parse_time(value: object) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    numerator = sum(float(a) * float(b) for a, b in zip(left, right))
    left_norm = math.sqrt(sum(float(value) * float(value) for value in left))
    right_norm = math.sqrt(sum(float(value) * float(value) for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return numerator / (left_norm * right_norm)


def _stable_digest(units: Iterable[Mapping[str, Any]]) -> str:
    logical = []
    for unit in units:
        search_text = "\n".join(
            str(unit.get(field, ""))
            for field in ("source_path", "heading", "content")
        )
        evidence = str(unit.get("serialized_evidence", ""))
        logical.append(
            {
                "unit_id": str(unit.get("unit_id", "")),
                "search_sha256": hashlib.sha256(search_text.encode("utf-8")).hexdigest(),
                "evidence_sha256": hashlib.sha256(evidence.encode("utf-8")).hexdigest(),
                "retrieval_metadata": {
                    key: unit.get(key)
                    for key in (
                        "applies_to",
                        "authority_sha256",
                        "context",
                        "context_ids",
                        "deleted_at",
                        "entities",
                        "negative_only",
                        "non_triggers",
                        "permission",
                        "relation_keys",
                        "related_unit_ids",
                        "scope",
                        "source_revision",
                        "status",
                        "superseded_by",
                        "supersedes",
                        "trust_class",
                        "valid_from",
                        "valid_to",
                    )
                },
            }
        )
    encoded = json.dumps(sorted(logical, key=lambda row: row["unit_id"]), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class HybridRetriever:
    """Bounded local sparse/dense union over already-governed atomic units."""

    def __init__(
        self,
        units: Iterable[Mapping[str, Any]],
        *,
        aliases: Optional[Mapping[str, str]] = None,
        dense_encoder: Optional[DenseEncoder] = None,
        dense_vectors: Optional[Mapping[str, Sequence[float]]] = None,
        enabled_channels: Optional[Sequence[str]] = None,
    ) -> None:
        self.enabled_channels = (
            set(RETRIEVAL_CHANNELS)
            if enabled_channels is None
            else {str(channel) for channel in enabled_channels}
        )
        unknown_channels = self.enabled_channels - RETRIEVAL_CHANNELS
        if unknown_channels:
            raise ValueError(f"unknown retrieval channels: {sorted(unknown_channels)}")
        self.units = [dict(unit) for unit in units]
        self.units.sort(key=lambda unit: str(unit.get("unit_id", "")))
        identifiers = [str(unit.get("unit_id", "")) for unit in self.units]
        if any(not identifier for identifier in identifiers) or len(set(identifiers)) != len(identifiers):
            raise ValueError("units require unique non-empty unit_id values")
        self.by_id = {str(unit["unit_id"]): unit for unit in self.units}
        self._superseded_replacements: dict[str, set[str]] = defaultdict(set)
        for unit in self.units:
            unit_id = str(unit["unit_id"])
            superseded_by = unit.get("superseded_by")
            replacement_ids = (
                superseded_by
                if isinstance(superseded_by, list)
                else [superseded_by]
                if superseded_by
                else []
            )
            for replacement_id in replacement_ids:
                replacement = str(replacement_id)
                if replacement in self.by_id and replacement != unit_id:
                    self._superseded_replacements[unit_id].add(replacement)
            supersedes = unit.get("supersedes")
            prior_ids = supersedes if isinstance(supersedes, list) else [supersedes] if supersedes else []
            for prior_id in prior_ids:
                prior = str(prior_id)
                if prior in self.by_id and prior != unit_id:
                    self._superseded_replacements[prior].add(unit_id)
        self.corpus_digest = _stable_digest(self.units)
        combined_aliases = dict(DEFAULT_ALIASES)
        if aliases:
            combined_aliases.update(aliases)
        self.aliases = {
            normalize_text(alias): normalize_text(canonical)
            for alias, canonical in combined_aliases.items()
            if normalize_text(alias) and normalize_text(canonical)
        }
        self._context_canonicals = set(CONTEXT_CANONICALS)
        self._normalized: dict[str, dict[str, Any]] = {}
        self._postings: dict[str, dict[str, int]] = defaultdict(dict)
        self._context_units: dict[str, set[str]] = defaultdict(set)
        self._identifier_units: dict[str, set[str]] = defaultdict(set)
        entity_postings: dict[str, set[str]] = defaultdict(set)
        for unit in self.units:
            identifier = str(unit["unit_id"])
            content = str(unit.get("content", ""))
            heading = str(unit.get("heading", ""))
            path = str(unit.get("source_path", ""))
            content_tokens = tokenize(content)
            heading_tokens = tokenize(heading)
            path_tokens = tokenize(path.replace("_", " ")) + tokenize(path)
            weighted = Counter(content_tokens)
            weighted.update({token: 3 for token in heading_tokens})
            weighted.update({token: 4 for token in path_tokens})
            normalized = {
                "content": normalize_text(content),
                "heading": normalize_text(heading),
                "path": normalize_text(path),
                "path_spaced": normalize_text(path).replace("_", " "),
                "path_words": frozenset(path_tokens),
                "tokens": frozenset(weighted),
                "tf": weighted,
                "identifiers": frozenset(extract_identifiers(" ".join((content, heading, path)))),
                "search_text": "\n".join(value for value in (path, heading, content) if value),
            }
            declared_entities = unit.get("entities")
            entities = set(extract_entities("\n".join((heading, content))))
            for declared_values in (declared_entities, unit.get("relation_keys")):
                if isinstance(declared_values, list):
                    entities.update(
                        normalize_text(entity)
                        for entity in declared_values
                        if isinstance(entity, str) and normalize_text(entity)
                    )
            normalized["entities"] = frozenset(entities)
            self._normalized[identifier] = normalized
            for structured_identifier in normalized["identifiers"]:
                self._identifier_units[structured_identifier].add(identifier)
            for entity in entities:
                entity_postings[entity].add(identifier)
            path_parts = [part for part in path.split("/") if part]
            if len(path_parts) >= 2 and path_parts[0] in {"work_contexts", "personal_knowledge"}:
                self._context_units[normalize_text(path_parts[1])].add(identifier)
            fixture_context = unit.get("context")
            if isinstance(fixture_context, str) and normalize_text(fixture_context):
                self._context_units[normalize_text(fixture_context)].add(identifier)
            for token, frequency in weighted.items():
                self._postings[token][identifier] = frequency
        self._entity_neighbors: dict[str, set[str]] = defaultdict(set)
        for entity, entity_unit_ids in entity_postings.items():
            if len(entity_unit_ids) < 2 or len(entity_unit_ids) > 8:
                continue
            for unit_id in entity_unit_ids:
                self._entity_neighbors[unit_id].update(entity_unit_ids - {unit_id})
        self._document_count = max(1, len(self.units))
        self._average_length = (
            sum(sum(value["tf"].values()) for value in self._normalized.values()) / self._document_count
        )
        self._dense_encoder = dense_encoder
        self._dense_vectors: dict[str, Sequence[float]] = {}
        self._dense_status = "disabled"
        self._dense_reason = "not_configured"
        if "dense" not in self.enabled_channels:
            self._dense_status = "disabled"
            self._dense_reason = "channel_disabled"
        elif dense_encoder is not None and dense_vectors is not None:
            supplied_ids = set(dense_vectors)
            if supplied_ids != set(identifiers):
                self._dense_status = "unavailable"
                self._dense_reason = "vector_set_mismatch"
            else:
                self._dense_vectors = {
                    identifier: dense_vectors[identifier]
                    for identifier in identifiers
                }
                self._dense_status = "ready"
                self._dense_reason = "verified_local_cache"
        elif dense_encoder is not None and self.units:
            try:
                vectors = list(dense_encoder.encode([self._normalized[identifier]["search_text"] for identifier in identifiers]))
                if len(vectors) != len(identifiers):
                    raise ValueError("dense vector count mismatch")
                self._dense_vectors = dict(zip(identifiers, vectors))
            except Exception:
                self._dense_vectors = {}
                self._dense_status = "unavailable"
                self._dense_reason = "encoder_failed"
            else:
                self._dense_status = "ready"
                self._dense_reason = "local_model_loaded"

    def _query_tokens(self, value: object) -> list[str]:
        """Expand morphology only for OOV query words, preserving exact evidence ranking."""
        tokens = tokenize(value)
        expanded: list[str] = []
        for token in tokens:
            expanded.append(token)
            if token in self._postings:
                continue
            expanded.extend(
                variant
                for variant in english_lexical_variants(token)
                if variant in self._postings
            )
        return list(dict.fromkeys(expanded))

    @staticmethod
    def _eligible(
        unit: Mapping[str, Any],
        context: Mapping[str, Any],
        now: datetime,
    ) -> tuple[bool, Optional[str]]:
        status = str(unit.get("status", "active"))
        temporal_mode = str(context.get("temporal_mode", "current"))
        historical = temporal_mode in {"historical", "timeline"}
        if status == "deleted" or unit.get("deleted_at"):
            return False, "deleted"
        if status in {"deprecated", "archived", "invalidated"}:
            return False, "superseded"
        if (status == "superseded" or unit.get("superseded_by")) and not historical:
            return False, "superseded"
        if status not in {"active", "legacy", "superseded"}:
            return False, "not_active"
        permission = unit.get("permission")
        if permission is not None and str(permission) != "allowed":
            return False, "permission_filtered"
        scopes = context.get("scopes")
        unit_scope = str(unit.get("scope", "global"))
        if not isinstance(scopes, list) or not scopes:
            if unit_scope != "global":
                return False, "scope_required"
        elif unit_scope not in scopes:
            return False, "scope_filtered"
        requested_platform = context.get("applies_to")
        applies_to = str(unit.get("applies_to", "all"))
        if requested_platform and applies_to not in {"all", str(requested_platform)}:
            return False, "scope_filtered"
        source_prefixes = context.get("source_prefixes")
        if isinstance(source_prefixes, list) and source_prefixes:
            if not any(str(unit.get("source_path", "")).startswith(str(prefix)) for prefix in source_prefixes):
                return False, "source_filtered"
        valid_from = _parse_time(unit.get("valid_from"))
        valid_to = _parse_time(unit.get("valid_to"))
        if (unit.get("valid_from") not in (None, "") and valid_from is None) or (
            unit.get("valid_to") not in (None, "") and valid_to is None
        ):
            return False, "invalid_timestamp"
        if valid_from is not None and now < valid_from:
            return False, "not_yet_valid"
        if valid_to is not None and now >= valid_to:
            if temporal_mode == "timeline":
                pass
            elif not historical or context.get("temporal_reference_explicit"):
                return False, "expired"
        if context.get("high_stakes") and str(unit.get("trust_class", "canonical_legacy")) != "current_source_validated":
            return False, "current_source_required"
        return True, None

    def _query(self, query: str) -> dict[str, Any]:
        normalized = normalize_text(query)
        all_aliases = (
            [
                (alias, canonical)
                for alias, canonical in self.aliases.items()
                if alias in normalized
            ]
            if "alias" in self.enabled_channels
            else []
        )
        negated_contexts = {
            canonical
            for alias, canonical in all_aliases
            if canonical in self._context_canonicals
            and _alias_is_explicitly_negated(normalized, alias)
        }
        aliases = [
            (alias, canonical)
            for alias, canonical in all_aliases
            if canonical not in negated_contexts
        ]
        expanded = normalized + " " + " ".join(canonical for _alias, canonical in aliases)
        tokens = [token for token in self._query_tokens(expanded) if token not in QUERY_NOISE]
        focus = normalized
        focus = re.sub(r"^请从.+?中找回关于", "", focus)
        focus = re.sub(r"^请\s+retrieve\s+", "", focus)
        focus = re.sub(r"^retrieve the durable evidence for\s+", "", focus)
        focus = re.sub(r"^retrieve\s+", "", focus)
        focus = re.sub(r"的权威记忆证据.*$", "", focus)
        focus = re.sub(r"[,，]?并保留\s+source evidence.*$", "", focus)
        context_aliases = [
            (alias, canonical)
            for alias, canonical in aliases
            if canonical in self._context_canonicals
        ]
        role_aliases = [
            (alias, canonical)
            for alias, canonical in aliases
            if canonical not in self._context_canonicals
        ]
        for alias, _canonical in context_aliases:
            focus = re.sub(r"\s+in\s+" + re.escape(alias) + r"[.,，。;；]*\s*$", "", focus)
            focus = focus.replace(alias, " ")
        for alias, canonical in role_aliases:
            focus = focus.replace(alias, " " + canonical + " ")
        focus_tokens = [token for token in self._query_tokens(focus) if token not in QUERY_NOISE]
        identifiers = extract_identifiers(normalized)
        concepts = detect_context_concepts(normalized)
        return {
            "normalized": normalized,
            "tokens": list(dict.fromkeys(tokens)),
            "focus": normalize_text(focus).strip(" ,.;，。|｜"),
            "focus_tokens": list(dict.fromkeys(focus_tokens)),
            "identifiers": identifiers,
            "concepts": concepts,
            "relation_intent": detect_multihop_relation_intent(normalized),
            "aliases": aliases,
            "context_aliases": context_aliases,
            "negated_contexts": negated_contexts,
        }

    def _terminal_replacements(
        self,
        seed_id: str,
        eligible_ids: set[str],
    ) -> set[str]:
        """Resolve declared supersession to eligible terminals, failing closed on bad branches."""
        terminals: set[str] = set()
        visited = {seed_id}
        queue = sorted(self._superseded_replacements.get(seed_id, set()))
        while queue and len(visited) <= MAX_INTERNAL_CANDIDATES:
            unit_id = queue.pop(0)
            if unit_id in visited:
                continue
            visited.add(unit_id)
            replacements = self._superseded_replacements.get(unit_id, set())
            if replacements:
                queue.extend(sorted(replacements - visited))
                continue
            if unit_id in eligible_ids:
                terminals.add(unit_id)
        return terminals

    @staticmethod
    def _matches_non_trigger(unit: Mapping[str, Any], normalized_query: str) -> bool:
        non_triggers = unit.get("non_triggers")
        if not isinstance(non_triggers, list):
            return False
        query_tokens = {
            token for token in tokenize(normalized_query) if token not in QUERY_NOISE
        }
        for non_trigger in non_triggers:
            if not isinstance(non_trigger, str):
                continue
            normalized_non_trigger = normalize_text(non_trigger)
            if not normalized_non_trigger:
                continue
            if normalized_non_trigger == normalized_query or normalized_non_trigger in normalized_query:
                return True
            non_trigger_tokens = {
                token
                for token in tokenize(normalized_non_trigger)
                if token not in QUERY_NOISE
            }
            overlap = query_tokens & non_trigger_tokens
            if len(overlap) >= 3 and len(overlap) / max(1, len(non_trigger_tokens)) >= 0.55:
                return True
        return False

    def _relation_rows(
        self,
        *,
        seeds: Sequence[tuple[str, float]],
        eligible_ids: set[str],
        focus_tokens: set[str],
        expand_corpus_entities: bool,
        limit: int,
    ) -> tuple[
        list[tuple[str, float]],
        dict[str, list[str]],
        dict[str, int | bool],
    ]:
        """Expand explicit and corpus-derived relations without making every sparse hit strong."""
        trace: Counter[str] = Counter()
        trace["focus_token_count"] = len(focus_tokens)
        trace["seed_count"] = len(seeds)
        attested_focus_tokens = {
            token for token in focus_tokens if token in self._postings
        }
        trace["attested_focus_token_count"] = len(attested_focus_tokens)
        scored_focus_tokens = (
            attested_focus_tokens if expand_corpus_entities else focus_tokens
        )
        if len(scored_focus_tokens) < 2:
            return [], {}, {
                **dict(trace),
                "emitted_chain_count": 0,
                "intent_detected": expand_corpus_entities,
                "rescored_candidate_count": 0,
            }
        relation_scores: dict[str, float] = {}
        relation_chains: dict[str, list[str]] = {}
        claimed: set[str] = set()
        for seed_id, seed_score in seeds:
            if seed_id in claimed:
                continue
            seed_has_eligible_edge = False
            queue = [(seed_id, 0)]
            enqueued = {seed_id}
            visited: dict[str, int] = {}
            parents: dict[str, Optional[str]] = {seed_id: None}
            while queue and len(visited) < limit:
                queue.sort(
                    key=lambda item: (
                        -len(
                            scored_focus_tokens
                            & self._normalized[item[0]]["tokens"]
                        ),
                        -int(bool(self.by_id[item[0]].get("related_unit_ids"))),
                        item[1],
                        item[0],
                    )
                )
                unit_id, depth = queue.pop(0)
                if unit_id in visited:
                    continue
                visited[unit_id] = depth
                if depth >= 2:
                    trace["terminal_node_count"] += 1
                    continue
                declared = self.by_id[unit_id].get("related_unit_ids")
                related_ids = (
                    set(self._entity_neighbors.get(unit_id, set()))
                    if expand_corpus_entities
                    else set()
                )
                if isinstance(declared, list):
                    related_ids.update(str(value) for value in declared)
                trace["edge_candidate_count"] += len(related_ids)
                added_neighbor = False
                for related_id_value in sorted(related_ids):
                    related_id = str(related_id_value)
                    if related_id not in eligible_ids:
                        trace["ineligible_edge_count"] += 1
                        continue
                    if related_id in visited or related_id in enqueued:
                        trace["duplicate_edge_count"] += 1
                        continue
                    parents[related_id] = unit_id
                    queue.append((related_id, depth + 1))
                    enqueued.add(related_id)
                    added_neighbor = True
                    seed_has_eligible_edge = True
                    trace["eligible_edge_count"] += 1
                if not added_neighbor:
                    trace["terminal_node_count"] += 1
            trace["visited_node_count"] += len(visited)
            trace["seed_with_eligible_edge_count"] += int(seed_has_eligible_edge)
            if len(visited) < 2:
                continue
            directly_relevant = {
                unit_id
                for unit_id in visited
                if scored_focus_tokens & self._normalized[unit_id]["tokens"]
            }
            trace["directly_relevant_node_count"] += len(directly_relevant)
            included: set[str] = set()
            for unit_id in directly_relevant:
                cursor: Optional[str] = unit_id
                while cursor is not None:
                    included.add(cursor)
                    cursor = parents[cursor]
            claimed.update(included)
            covered: set[str] = set()
            for unit_id in included:
                covered.update(
                    scored_focus_tokens & self._normalized[unit_id]["tokens"]
                )
            collective_coverage = len(covered) / len(scored_focus_tokens)
            if collective_coverage < 0.60:
                continue
            trace["coverage_pass_seed_count"] += 1
            for unit_id in included:
                depth = visited[unit_id]
                direct_coverage = len(
                    scored_focus_tokens & self._normalized[unit_id]["tokens"]
                ) / len(scored_focus_tokens)
                score = collective_coverage + 0.10 * direct_coverage + 0.01 * seed_score - 0.01 * depth
                chain: list[str] = []
                cursor: Optional[str] = unit_id
                while cursor is not None:
                    chain.append(cursor)
                    cursor = parents[cursor]
                chain.reverse()
                if score > relation_scores.get(unit_id, -math.inf):
                    relation_scores[unit_id] = score
                    relation_chains[unit_id] = chain
        rows = sorted(relation_scores.items(), key=lambda row: (-row[1], row[0]))[:limit]
        bounded_chains = {
            unit_id: relation_chains[unit_id] for unit_id, _score in rows
        }
        return rows, bounded_chains, {
            **dict(trace),
            "claimed_unit_count": len(claimed),
            "emitted_chain_count": sum(
                len(chain) >= 2 for chain in bounded_chains.values()
            ),
            "intent_detected": expand_corpus_entities,
            "rescored_candidate_count": len(rows),
        }

    def search(
        self,
        query: str,
        *,
        context: Optional[Mapping[str, Any]] = None,
        now: Optional[datetime] = None,
        top_k: int = TOP_K,
        max_characters: int = MAX_TOTAL_CHARACTERS,
        internal_limit: int = MAX_INTERNAL_CANDIDATES,
        minimum_focus_coverage: float = 0.60,
        minimum_focus_matches: int = 2,
    ) -> dict[str, Any]:
        if not isinstance(query, str) or not query.strip():
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": [], "internal_candidates": 0}
        output_limit = min(TOP_K, max(1, int(top_k)))
        character_limit = min(MAX_TOTAL_CHARACTERS, max(0, int(max_characters)))
        candidate_limit = min(MAX_INTERNAL_CANDIDATES, max(1, int(internal_limit)))
        coverage_floor = min(1.0, max(0.0, float(minimum_focus_coverage)))
        match_floor = max(1, int(minimum_focus_matches))
        query_info = self._query(query)
        if not query_info["tokens"] and not query_info["identifiers"]:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": [], "internal_candidates": 0}
        effective_context = dict(context or {})
        effective_context.setdefault("temporal_mode", detect_temporal_mode(query))
        effective_context["temporal_reference_explicit"] = now is not None
        temporal_mode = str(effective_context.get("temporal_mode", "current"))
        checked_at = now or datetime.now(timezone.utc)
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)
        checked_at = checked_at.astimezone(timezone.utc)
        filters: Counter[str] = Counter()
        eligible_ids: set[str] = set()
        for unit in self.units:
            if unit.get("negative_only") is True:
                filters["negative_only"] += 1
                continue
            context_ids = unit.get("context_ids")
            if (
                isinstance(context_ids, list)
                and query_info["negated_contexts"].intersection(
                    str(context_id) for context_id in context_ids
                )
            ):
                filters["negated_context"] += 1
                continue
            if self._matches_non_trigger(unit, query_info["normalized"]):
                filters["non_trigger"] += 1
                continue
            eligible, reason = self._eligible(unit, effective_context, checked_at)
            if eligible:
                eligible_ids.add(str(unit["unit_id"]))
            elif reason:
                filters[reason] += 1

        routed_ids: set[str] = set()
        for _alias, canonical in query_info["context_aliases"]:
            underscored = canonical.replace(" ", "_")
            for unit_id in eligible_ids:
                path = self._normalized[unit_id]["path"]
                if f"/{underscored}/" in f"/{path}/" or f"/{underscored}." in f"/{path}":
                    routed_ids.add(unit_id)
        if routed_ids:
            filters["alias_scope_filtered"] += len(eligible_ids - routed_ids)
            eligible_ids = routed_ids

        lane_size = min(20, candidate_limit)
        lanes: dict[str, list[tuple[str, float]]] = {}

        identifier_rows: list[tuple[str, float]] = []
        if "identifier" in self.enabled_channels:
            identifier_scores: Counter[str] = Counter()
            for identifier in query_info["identifiers"]:
                matching_ids = sorted(
                    self._identifier_units.get(identifier, set()) & eligible_ids
                )
                specificity = math.log(
                    1.0 + len(eligible_ids) / max(1, len(matching_ids))
                )
                for unit_id in matching_ids:
                    identifier_scores[unit_id] += specificity
            identifier_rows = sorted(
                identifier_scores.items(), key=lambda row: (-row[1], row[0])
            )[:lane_size]
        if identifier_rows:
            lanes["identifier"] = identifier_rows

        sparse_scores: Counter[str] = Counter()
        lifecycle_seed_scores: Counter[str] = Counter()
        if "sparse" in self.enabled_channels:
            for token in query_info["tokens"]:
                posting = self._postings.get(token, {})
                if not posting:
                    continue
                document_frequency = len(posting)
                inverse_frequency = math.log(1.0 + (self._document_count - document_frequency + 0.5) / (document_frequency + 0.5))
                for unit_id, frequency in posting.items():
                    length = sum(self._normalized[unit_id]["tf"].values())
                    denominator = frequency + 1.2 * (0.25 + 0.75 * length / max(1.0, self._average_length))
                    score = inverse_frequency * (frequency * 2.2 / denominator)
                    if unit_id in eligible_ids:
                        sparse_scores[unit_id] += score
                    elif unit_id in self._superseded_replacements:
                        unit = self.by_id[unit_id]
                        if str(unit.get("status", "active")) == "superseded" and not unit.get("deleted_at"):
                            lifecycle_seed_scores[unit_id] += score
        if sparse_scores:
            lanes["sparse"] = sorted(sparse_scores.items(), key=lambda row: (-row[1], row[0]))[:lane_size]

        lifecycle_scores: dict[str, float] = {}
        if "lifecycle" in self.enabled_channels and temporal_mode == "current":
            for seed_id, seed_score in lifecycle_seed_scores.items():
                for replacement_id in self._terminal_replacements(seed_id, eligible_ids):
                    lifecycle_scores[replacement_id] = max(
                        lifecycle_scores.get(replacement_id, 0.0),
                        float(seed_score),
                    )
        if lifecycle_scores:
            lanes["lifecycle"] = sorted(
                lifecycle_scores.items(), key=lambda row: (-row[1], row[0])
            )[:lane_size]

        relation_seeds = lanes.get("sparse", [])
        relation_seed_gate_applied = False
        if query_info["relation_intent"]:
            bounded_identifier_units: set[str] = set()
            for identifier in query_info["identifiers"]:
                identifier_units = self._identifier_units.get(identifier, set())
                if 2 <= len(identifier_units) <= MAX_CONCEPT_CLUSTER_SIZE:
                    bounded_identifier_units.update(identifier_units & eligible_ids)
            gated_relation_seeds = [
                row for row in relation_seeds if row[0] in bounded_identifier_units
            ]
            if gated_relation_seeds:
                relation_seeds = gated_relation_seeds
                relation_seed_gate_applied = True

        relation_rows, relation_chains, relation_trace = (
            self._relation_rows(
                seeds=relation_seeds,
                eligible_ids=eligible_ids,
                focus_tokens=set(query_info["focus_tokens"]),
                expand_corpus_entities=bool(query_info["relation_intent"]),
                limit=lane_size,
            )
            if "relation" in self.enabled_channels
            else (
                [],
                {},
                {
                    "emitted_chain_count": 0,
                    "intent_detected": bool(query_info["relation_intent"]),
                    "rescored_candidate_count": 0,
                    "seed_count": len(lanes.get("sparse", [])),
                },
            )
        )
        relation_trace["seed_gate_applied"] = relation_seed_gate_applied
        if relation_rows:
            lanes["relation"] = relation_rows

        temporal_rows: list[tuple[str, float]] = []
        if "temporal" in self.enabled_channels and temporal_mode in {"historical", "timeline"}:
            for unit_id, sparse_score in lanes.get("sparse", []):
                unit = self.by_id[unit_id]
                if str(unit.get("status", "active")) == "superseded" or unit.get("superseded_by"):
                    temporal_rows.append((unit_id, 2.0 + sparse_score))
                elif temporal_mode == "timeline":
                    temporal_rows.append((unit_id, 1.0 + sparse_score))
        if temporal_rows:
            lanes["temporal"] = sorted(
                temporal_rows, key=lambda row: (-row[1], row[0])
            )[:lane_size]

        concept_rows: list[tuple[str, float]] = []
        if "concept" in self.enabled_channels and not query_info["context_aliases"]:
            for concept in query_info["concepts"]:
                for unit_id in self._context_units.get(concept, set()) & eligible_ids:
                    concept_rows.append((unit_id, 1.0 + sparse_scores.get(unit_id, 0.0)))
        if concept_rows:
            concept_scores = {unit_id: score for unit_id, score in concept_rows}
            lanes["concept"] = sorted(
                concept_scores.items(), key=lambda row: (-row[1], row[0])
            )[:lane_size]

        phrase_rows: list[tuple[str, float]] = []
        focus = str(query_info["focus"])
        if "phrase" in self.enabled_channels:
            for unit_id in eligible_ids:
                document = self._normalized[unit_id]
                score = 0.0
                if focus and focus == document["heading"]:
                    score = 3.0
                elif focus and len(focus) >= 4 and focus in document["heading"]:
                    score = 2.5
                elif focus and len(focus) >= 8 and focus in document["content"]:
                    score = 2.0
                if score:
                    phrase_rows.append((unit_id, score))
        if phrase_rows:
            lanes["phrase"] = sorted(phrase_rows, key=lambda row: (-row[1], row[0]))[:lane_size]

        alias_rows: list[tuple[str, float]] = []
        path_rows: list[tuple[str, float]] = []
        canonical_aliases = [canonical for _alias, canonical in query_info["context_aliases"]]
        if canonical_aliases and self.enabled_channels & {"alias", "path"}:
            query_path_tokens = set(tokenize(" ".join(canonical_aliases)))
            for unit_id in eligible_ids:
                document = self._normalized[unit_id]
                path = document["path"]
                path_spaced = document["path_spaced"]
                alias_score = sum(
                    1.0
                    for canonical in canonical_aliases
                    if canonical.replace(" ", "_") in path or canonical.replace("_", " ") in path_spaced
                )
                if alias_score and "alias" in self.enabled_channels:
                    alias_rows.append((unit_id, alias_score * 1000.0 + sparse_scores.get(unit_id, 0.0)))
                overlap = query_path_tokens & document["path_words"]
                if overlap and "path" in self.enabled_channels:
                    path_rows.append(
                        (
                            unit_id,
                            1000.0 * len(overlap) / max(1, len(query_path_tokens))
                            + sparse_scores.get(unit_id, 0.0),
                        )
                    )
        if alias_rows:
            lanes["alias"] = sorted(alias_rows, key=lambda row: (-row[1], row[0]))[:lane_size]
        if path_rows:
            lanes["path"] = sorted(path_rows, key=lambda row: (-row[1], row[0]))[:lane_size]

        dense_info = {"status": self._dense_status, "reason": self._dense_reason}
        if "dense" in self.enabled_channels and self._dense_status == "ready" and self._dense_encoder is not None:
            try:
                query_vectors = list(self._dense_encoder.encode([query]))
                if len(query_vectors) != 1:
                    raise ValueError("dense query vector count mismatch")
                dense_rows = [
                    (unit_id, _cosine(query_vectors[0], vector))
                    for unit_id, vector in self._dense_vectors.items()
                    if unit_id in eligible_ids
                ]
                dense_rows = [row for row in dense_rows if row[1] > 0.0]
                if dense_rows:
                    lanes["dense"] = sorted(dense_rows, key=lambda row: (-row[1], row[0]))[:lane_size]
                dense_info = {"status": "used", "reason": "local_model"}
            except Exception:
                dense_info = {"status": "unavailable", "reason": "encoder_failed"}

        weights = {
            "identifier": 5.0,
            "lifecycle": 4.0,
            "relation": 3.5,
            "temporal": 3.4,
            "phrase": 3.0,
            "alias": 2.2,
            "concept": 2.0,
            "path": 1.8,
            "sparse": 1.4,
            "dense": 1.0,
        }
        channel_details: dict[str, dict[str, dict[str, float | int]]] = defaultdict(dict)
        fusion: Counter[str] = Counter()
        for channel, rows in lanes.items():
            for rank, (unit_id, raw_score) in enumerate(rows, 1):
                fusion[unit_id] += weights[channel] / (RRF_K + rank)
                channel_details[unit_id][channel] = {"rank": rank, "score": round(float(raw_score), 6)}
        fused = sorted(fusion.items(), key=lambda row: (-row[1], row[0]))[:candidate_limit]

        focus_tokens = set(query_info["focus_tokens"])
        reranked: list[dict[str, Any]] = []
        for unit_id, rrf_score in fused:
            document = self._normalized[unit_id]
            channels = channel_details[unit_id]
            matched_focus = focus_tokens & document["tokens"]
            coverage = len(matched_focus) / max(1, len(focus_tokens))
            dense_score = float(channels.get("dense", {}).get("score", 0.0))
            exact_phrase = "phrase" in channels
            strong = bool(
                "identifier" in channels
                or "lifecycle" in channels
                or "relation" in channels
                or "temporal" in channels
                or exact_phrase
                or "concept" in channels
                or ("alias" in channels and "path" in channels and (coverage > 0.0 or not focus_tokens))
                or (coverage >= coverage_floor and len(matched_focus) >= match_floor)
                or dense_score >= 0.72
            )
            if not strong:
                continue
            rerank_score = rrf_score + 0.025 * coverage + 0.006 * min(4, len(channels))
            if document["heading"] and focus == document["heading"]:
                rerank_score += 0.04
            relation_chain = relation_chains.get(unit_id, [])
            if query_info["relation_intent"] and relation_seed_gate_applied:
                rerank_score += 0.04 * min(2, max(0, len(relation_chain) - 1))
            reranked.append(
                {
                    "unit_id": unit_id,
                    "score": rerank_score,
                    "coverage": coverage,
                    "channels": channels,
                    "tokens": document["tokens"],
                    "source_path": str(self.by_id[unit_id].get("source_path", "")),
                    "relation_chain": relation_chain,
                }
            )
        reranked.sort(key=lambda row: (-row["score"], row["unit_id"]))

        selected: list[dict[str, Any]] = []
        remaining = list(reranked)
        while remaining and len(selected) < output_limit:
            best_index = 0
            best_value = -math.inf
            for index, candidate in enumerate(remaining):
                maximum_similarity = 0.0
                for chosen in selected:
                    union = candidate["tokens"] | chosen["tokens"]
                    similarity = len(candidate["tokens"] & chosen["tokens"]) / max(1, len(union))
                    if candidate["source_path"] == chosen["source_path"]:
                        similarity = max(similarity, 0.35)
                    maximum_similarity = max(maximum_similarity, similarity)
                novelty = 0.018 if selected and all(candidate["source_path"] != chosen["source_path"] for chosen in selected) else 0.0
                value = candidate["score"] + novelty - 0.06 * maximum_similarity
                if value > best_value:
                    best_value = value
                    best_index = index
            selected.append(remaining.pop(best_index))

        matches: list[dict[str, Any]] = []
        used_characters = 0
        for selected_row in selected:
            unit = self.by_id[selected_row["unit_id"]]
            evidence = str(unit.get("serialized_evidence") or unit.get("content", ""))[:MAX_HIT_CHARACTERS]
            if used_characters + len(evidence) > character_limit:
                remaining_characters = character_limit - used_characters
                if remaining_characters <= 0:
                    break
                evidence = evidence[:remaining_characters]
            matches.append(
                {
                    "unit_id": selected_row["unit_id"],
                    "source_path": selected_row["source_path"],
                    "evidence": evidence,
                    "score": round(float(selected_row["score"]), 8),
                    "channels": selected_row["channels"],
                    "matched_terms": sorted(focus_tokens & selected_row["tokens"])[:12],
                    "relation_chain": selected_row["relation_chain"],
                }
            )
            used_characters += len(evidence)
        return {
            "schema_version": 1,
            "status": "hit" if matches else "no_safe_match",
            "backend": "local_hybrid_rrf",
            "normalization": NORMALIZATION_VERSION,
            "corpus_digest": self.corpus_digest,
            "internal_candidates": min(candidate_limit, len(fused)),
            "candidate_channels": {channel: len(rows) for channel, rows in sorted(lanes.items())},
            "dense": dense_info,
            "filtered": dict(sorted(filters.items())),
            "reason_codes": [] if matches else ["confidence_below_threshold"],
            "trace": {"relation": relation_trace},
            "matches": matches,
        }

