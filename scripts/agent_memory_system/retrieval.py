from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import struct
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from memory_control_plane.projection import MemoryProjection, parse_time
from memory_control_plane.recall_policy import (
    RecallPolicy,
    RecallPolicyError,
    parse_recall_policy,
    validate_recall_request_binding,
)


MAX_QUERY_BYTES = 8 * 1024
MAX_EVIDENCE_CHARS = 2400
RRF_K = 60
SEMANTIC_THRESHOLD = 0.60
MAX_CANDIDATES = 200
INDEX_SCHEMA_VERSION = 4
INDEX_ADMISSION_POLICY = "stable_committed_authority_v1"
SEMANTIC_TEXT_MAX_BYTES = 4 * 1024
SEMANTIC_SEGMENT_TARGET_BYTES = 3 * 1024
SEMANTIC_HEADING_MAX_BYTES = 512
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
LATIN_TOKEN = re.compile(
    r"[a-z0-9]+(?:[._/+:-][a-z0-9]+)*",
    re.IGNORECASE,
)
AUTHORITY_PATH_TOKEN = re.compile(
    r"(?:core|platform|learnings)/[A-Za-z0-9._/-]+\.md", re.IGNORECASE
)
MARKDOWN_NAME_TOKEN = re.compile(
    r"(?<![A-Za-z0-9._/-])[A-Za-z0-9][A-Za-z0-9._-]*\.md", re.IGNORECASE
)
RETIRED_MEMORY_QUERY = re.compile(
    r"(?:\b(?:retired|deleted|tombstoned|obsolete)\b.*"
    r"\b(?:token|memory|preference|command|value)\b)"
    r"|(?:(?:已删除|已退休|已废弃|已淘汰|旧版)(?:的)?[^。！？\n]{0,80}"
    r"(?:记忆|令牌|偏好|命令|值))",
    re.IGNORECASE,
)
EMBEDDING_MANIFEST_KEYS = (
    "provider",
    "model",
    "dimension",
    "fingerprint",
    "privacy",
    "network",
)

# Deterministic local query expansion for durable memory concepts.  These are
# domain-level bilingual aliases, never item IDs or fixture answers.  They are
# applied before candidate generation and still require canonical reopen,
# scope/lifecycle/privacy eligibility, and term presence in the reopened chunk.
DEFAULT_ALIAS_CONCEPTS: Tuple[Tuple[Tuple[str, ...], Tuple[str, ...]], ...] = (
    (("旧规则", "过期规则", "outdated rule", "stale rule"),
     ("canonical authority", "revision", "权威", "版本", "重开")),
    (("source", "original", "原文", "来源"),
     ("canonical authority", "revision", "召回", "重开", "权威", "来源")),
    (("deletion", "delete", "删除", "墓碑"),
     ("tombstone", "墓碑", "传播", "旧条目", "索引")),
    (("interrupt", "continue", "resume", "中断", "续跑"),
     ("checkpoint", "检查点", "持久", "恢复", "继续")),
    (("compress", "offload", "压缩", "大量工具"),
     ("上下文", "offload", "摘要", "原始", "证据", "下钻")),
    (("drill", "回溯", "原始输出"),
     ("raw handle", "句柄", "内容", "哈希", "回放", "下钻")),
    (("private", "egress", "network egress", "私人", "出站", "传出", "数据传出"),
     ("local-only", "local", "network egress", "隐私", "embedding", "本地", "向量")),
    (("profile", "画像", "高影响偏好"),
     ("用户画像", "长期偏好", "显式授权", "approval gate")),
    (("conflict", "冲突"),
     ("候选", "冲突", "治理", "授权", "quarantine")),
    (("duplicate", "dedup", "重复", "避免重复"),
     ("候选", "幂等", "去重", "deduplication")),
    (("stall", "stalled", "卡住", "停滞", "后台"),
     ("worker", "健康检查", "告警", "恢复", "队列")),
    (("embedding", "semantic", "语义", "向量"),
     ("向量", "语义", "不可用", "降级", "lexical")),
    (("index", "search", "索引", "检索"),
     ("中文", "词法", "索引", "陈旧", "重建", "来源版本")),
)


@dataclass(frozen=True)
class AuthorityChunk:
    heading_id: str
    chunk_id: str
    item_id: str
    ordinal: int
    segment_index: int
    segment_digest: str
    heading: str
    start_line: int
    end_line: int
    text: str


def _normalized(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def default_alias_terms(query: str) -> List[str]:
    folded = _normalized(query)
    result: List[str] = []
    for triggers, expansions in DEFAULT_ALIAS_CONCEPTS:
        if any(_normalized(trigger) in folded for trigger in triggers):
            result.extend(expansions)
    return list(dict.fromkeys(result))


def _index_admission_reasons(item: Mapping[str, Any]) -> List[str]:
    """Filter only structurally unsafe authority before local indexing.

    Scope, platform, time, and query-specific authorization remain owned by the
    request RecallPolicy.  Keeping those dynamic axes out of this projection
    prevents a narrower build request from making a later authorized recall
    impossible without a rebuild.
    """

    reasons: List[str] = []
    if item.get("lifecycle") not in {"active", "legacy"}:
        reasons.append("lifecycle")
    if item.get("authorization_state") not in {"not_required", "user_approved"}:
        reasons.append("authorization")
    if item.get("provenance_trust") not in {
        "canonical_legacy",
        "current_source_validated",
        "source_bound_candidate",
    }:
        reasons.append("provenance_trust")
    if item.get("privacy_class") not in {"public", "private_local"}:
        reasons.append("privacy")
    if item.get("deleted") is True:
        reasons.append("deleted")
    if item.get("tombstoned") is True:
        reasons.append("tombstone")
    for field in ("revision_sha256", "content_sha256"):
        value = item.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            reasons.append("source_integrity")
            break
    return sorted(set(reasons))


def _index_admission_trace(
    items: Sequence[Mapping[str, Any]], *, stage: str
) -> List[Dict[str, Any]]:
    trace: List[Dict[str, Any]] = []
    for item in sorted(items, key=lambda row: str(row["item_id"])):
        reasons = _index_admission_reasons(item)
        reason_set = set(reasons)
        trace.append(
            {
                "id": str(item["item_id"]),
                "stage": stage,
                "checks": {
                    "scope": True,
                    "time": True,
                    "lifecycle": "lifecycle" not in reason_set,
                    "authorization": "authorization" not in reason_set,
                    "provenance_trust": "provenance_trust" not in reason_set,
                    "trust": not bool(
                        reason_set & {"authorization", "provenance_trust"}
                    ),
                    "privacy": "privacy" not in reason_set,
                    "tombstone": not bool(reason_set & {"deleted", "tombstone"}),
                    "source_integrity": "source_integrity" not in reason_set,
                },
                "result": "eligible" if not reasons else "filtered",
                "reason_codes": reasons,
                "authority_revision_sha256": str(item["revision_sha256"]),
            }
        )
    return trace


def _is_cjk(character: str) -> bool:
    point = ord(character)
    return (
        0x3400 <= point <= 0x4DBF
        or 0x4E00 <= point <= 0x9FFF
        or 0xF900 <= point <= 0xFAFF
        or 0x3040 <= point <= 0x30FF
        or 0xAC00 <= point <= 0xD7AF
    )


def _cjk_runs(value: str) -> Iterable[str]:
    run: List[str] = []
    for character in _normalized(value):
        if _is_cjk(character):
            run.append(character)
        elif run:
            yield "".join(run)
            run = []
    if run:
        yield "".join(run)


def _lexical_features(value: str) -> Dict[str, int]:
    features: Dict[str, int] = {}
    for token in LATIN_TOKEN.findall(_normalized(value)):
        features["latin:" + token] = features.get("latin:" + token, 0) + 1
    for run in _cjk_runs(value):
        for width in (1, 2, 3):
            for offset in range(0, len(run) - width + 1):
                token = run[offset : offset + width]
                key = "cjk{}:{}".format(width, token)
                features[key] = features.get(key, 0) + 1
    return features


def _feature_hash(lane: str, feature: str) -> str:
    return hashlib.sha256((lane + "\0" + feature).encode("utf-8")).hexdigest()


def _canonical_lexical_relevance(
    query: str, alias_terms: Sequence[str], canonical_text: str
) -> bool:
    """Require a complete lexical term, not a coincidental CJK character.

    Character n-grams are intentionally broad candidate generators.  The
    canonical reopen gate is stricter: at least one full CJK run, Latin token,
    or governed alias expansion from the query must occur in the reopened
    authority chunk.  This preserves short Chinese recall while preventing a
    query such as ``妙记`` from accepting an unrelated document containing
    only ``记录``.
    """
    canonical = _normalized(canonical_text)
    terms = [query, *alias_terms]
    for term in terms:
        normalized = _normalized(str(term))
        if normalized and normalized in canonical:
            return True
        if any(len(run) >= 2 and run in canonical for run in _cjk_runs(str(term))):
            return True
        if any(token in LATIN_TOKEN.findall(canonical) for token in LATIN_TOKEN.findall(normalized)):
            return True
    return False


def _canonical_alias_coverage(alias_terms: Sequence[str], canonical_text: str) -> int:
    """Count distinct, complete governed aliases proven by canonical reopen.

    Candidate generation intentionally tolerates repeated character n-grams.
    Final ranking must not let repetition of one low-information alias outrank a
    document that covers several independent concepts from the governed alias
    expansion.
    """

    canonical = _normalized(canonical_text)
    normalized_terms = {
        _normalized(str(term))
        for term in alias_terms
        if _normalized(str(term))
    }
    return sum(term in canonical for term in normalized_terms)


def _exact_query_terms(query: str) -> Dict[str, List[str]]:
    normalized = _normalized(query)
    paths = [_normalized(match.group(0)) for match in AUTHORITY_PATH_TOKEN.finditer(query)]
    names = [_normalized(Path(path).name) for path in paths]
    names.extend(
        _normalized(match.group(0)) for match in MARKDOWN_NAME_TOKEN.finditer(query)
    )
    if AUTHORITY_PATH_TOKEN.fullmatch(query.strip()):
        paths.append(_normalized(query.strip()))
    if MARKDOWN_NAME_TOKEN.fullmatch(query.strip()):
        names.append(_normalized(query.strip()))
    return {
        "exact_path": list(dict.fromkeys(paths)),
        "exact_name": list(dict.fromkeys(names)),
        "exact_title": [normalized],
    }


def _canonical_query_coverage(
    query: str,
    alias_terms: Sequence[str],
    canonical_text: str,
    authority_path: str,
) -> float:
    """Measure distinct query concepts, with repeated fragments counting once."""

    canonical = _normalized(canonical_text + "\n" + authority_path)
    concepts: set[str] = {
        token
        for token in LATIN_TOKEN.findall(_normalized(query))
        if len(token) >= 2 and token not in {"the", "and", "for", "from", "how", "what"}
    }
    for run in _cjk_runs(query):
        if len(run) <= 3:
            concepts.add(run)
            continue
        for width in (2, 3):
            concepts.update(
                run[offset : offset + width]
                for offset in range(0, len(run) - width + 1)
            )
    concepts.update(
        _normalized(str(term))
        for term in alias_terms
        if len(_normalized(str(term))) >= 2
    )
    if not concepts:
        return 0.0
    return sum(concept in canonical for concept in concepts) / len(concepts)


def _matched_query_terms(query: str, canonical_text: str) -> List[str]:
    """Return human-readable query terms proven by reopened authority.

    The index deliberately uses broad character n-grams, but audit output
    should name only complete query runs/tokens that survive canonical reopen.
    This keeps Chinese substring recall explainable without exposing the
    internal n-gram universe as if every fragment were a user term.
    """
    canonical = _normalized(canonical_text)
    matched: List[str] = []
    for token in LATIN_TOKEN.findall(_normalized(query)):
        # A query such as ``quartz flow`` may match a hyphenated path/title.
        if token in canonical:
            matched.append(token)
    for run in _cjk_runs(query):
        if run and run in canonical:
            matched.append(run)
    return list(dict.fromkeys(matched))


def _query_centered_excerpt(
    value: str,
    query: str,
    alias_terms: Sequence[str],
    *,
    limit: int,
) -> str:
    """Keep the proven query/alias window instead of blindly taking the head."""

    if len(value) <= limit:
        return value
    folded = unicodedata.normalize("NFKC", value).casefold()
    needles: List[str] = []
    for term in (query, *alias_terms):
        normalized = unicodedata.normalize("NFKC", str(term)).casefold().strip()
        if normalized:
            needles.append(normalized)
        needles.extend(LATIN_TOKEN.findall(normalized))
        needles.extend(run for run in _cjk_runs(normalized) if len(run) >= 2)
    match_start = -1
    match_size = 0
    for needle in dict.fromkeys(needles):
        offset = folded.find(needle)
        if offset >= 0:
            match_start = offset
            match_size = len(needle)
            break
    if match_start < 0:
        return value[: limit - 1] + "…"
    prefix_size = 1
    suffix_size = 1
    content_budget = limit - prefix_size - suffix_size
    start = max(0, match_start - max(0, (content_budget - match_size) // 3))
    end = min(len(value), start + content_budget)
    if end - start < content_budget:
        start = max(0, end - content_budget)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(value) else ""
    excerpt = prefix + value[start:end] + suffix
    return excerpt[:limit]


def _vector_bytes(vector: Sequence[float]) -> bytes:
    return struct.pack("<{}f".format(len(vector)), *[float(value) for value in vector])


def _vector_from_bytes(value: bytes, dimension: int) -> List[float]:
    if len(value) != dimension * 4:
        raise ValueError("semantic vector dimension mismatch")
    return list(struct.unpack("<{}f".format(dimension), value))


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or not left:
        return -1.0
    numerator = sum(a * b for a, b in zip(left, right))
    left_norm = sum(value * value for value in left) ** 0.5
    right_norm = sum(value * value for value in right) ** 0.5
    if left_norm <= 0 or right_norm <= 0:
        return -1.0
    return numerator / (left_norm * right_norm)


def _bounded_utf8(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", "ignore").rstrip()


def _semantic_heading(value: str) -> str:
    return _bounded_utf8(value.strip() or "document", SEMANTIC_HEADING_MAX_BYTES)


def _semantic_text(chunk: AuthorityChunk) -> str:
    heading = _semantic_heading(chunk.heading)
    value = heading + ("\n" + chunk.text if chunk.text else "")
    if len(value.encode("utf-8")) > SEMANTIC_TEXT_MAX_BYTES:
        raise ValueError("semantic chunk exceeds internal size limit")
    return value


def embedding_manifest_mismatches(
    stored: Mapping[str, Any], current: Mapping[str, Any]
) -> list[str]:
    """Return every compatibility boundary that changed since index build."""
    return [key for key in EMBEDDING_MANIFEST_KEYS if stored.get(key) != current.get(key)]


def _body_start(lines: Sequence[str]) -> int:
    if not lines or lines[0] != "---":
        return 0
    for index in range(1, len(lines)):
        if lines[index] == "---":
            return index + 1
    return 0


def _split_utf8_line(value: str, limit: int) -> List[str]:
    """Split a single logical line without cutting inside a UTF-8 sequence."""

    encoded = value.encode("utf-8")
    pieces: List[str] = []
    offset = 0
    while len(encoded) - offset > limit:
        end = offset + limit
        while end > offset and end < len(encoded) and encoded[end] & 0xC0 == 0x80:
            end -= 1
        prefix = encoded[offset:end].decode("utf-8")
        if not prefix:
            raise ValueError("semantic segment byte budget is too small")
        whitespace = max(prefix.rfind(" "), prefix.rfind("\t"))
        if whitespace >= len(prefix) // 2:
            raw_piece = prefix[: whitespace + 1]
        else:
            raw_piece = prefix
        consumed = len(raw_piece.encode("utf-8"))
        piece = raw_piece.rstrip()
        if not piece:
            piece = prefix
            consumed = len(prefix.encode("utf-8"))
        pieces.append(piece)
        offset += consumed
        while offset < len(encoded) and encoded[offset] in b" \t":
            offset += 1
    remaining = encoded[offset:].decode("utf-8")
    if remaining or not pieces:
        pieces.append(remaining)
    return pieces


def _section_segments(
    lines: Sequence[str],
    *,
    content_start: int,
    section_end: int,
    heading: str,
    fallback_line: int,
) -> List[Tuple[int, int, str]]:
    """Build paragraph-friendly segments bounded by the embedding contract."""

    heading_bytes = len(_semantic_heading(heading).encode("utf-8"))
    body_limit = SEMANTIC_TEXT_MAX_BYTES - heading_bytes - 1
    if body_limit <= 0:
        raise ValueError("semantic heading leaves no body byte budget")
    target = min(SEMANTIC_SEGMENT_TARGET_BYTES, body_limit)
    result: List[Tuple[int, int, str]] = []
    current: List[str] = []
    current_start: Optional[int] = None
    current_end: Optional[int] = None

    def current_text(extra: Optional[str] = None) -> str:
        values = [*current, *([extra] if extra is not None else [])]
        return "\n".join(values).strip()

    def flush() -> None:
        nonlocal current, current_start, current_end
        text = current_text()
        if text:
            result.append((current_start or fallback_line, current_end or fallback_line, text))
        current = []
        current_start = None
        current_end = None

    for index in range(content_start, section_end):
        line_number = index + 1
        line = lines[index]
        if not line.strip():
            if current and len(current_text().encode("utf-8")) >= target:
                flush()
            elif current and current[-1] != "":
                current.append("")
                current_end = line_number
            continue
        for piece in _split_utf8_line(line, body_limit):
            candidate = current_text(piece)
            if current and len(candidate.encode("utf-8")) > body_limit:
                flush()
                candidate = piece.strip()
            if len(candidate.encode("utf-8")) > body_limit:
                raise ValueError("semantic line split exceeded body budget")
            if current_start is None:
                current_start = line_number
            current.append(piece)
            current_end = line_number
    flush()
    if not result:
        result.append((fallback_line, fallback_line, ""))
    return result


def _chunks(item: Mapping[str, Any]) -> List[AuthorityChunk]:
    text = str(item["content"])
    lines = text.splitlines()
    start = _body_start(lines)
    sections: List[Tuple[int, int, str, int]] = []
    current_start = start
    current_heading = Path(str(item["authority_path"])).stem
    current_heading_line = start
    for index in range(start, len(lines)):
        matched = HEADING.match(lines[index])
        if matched is None:
            continue
        if any(line.strip() for line in lines[current_start:index]):
            sections.append((current_start, index, current_heading, current_heading_line))
        current_start = index
        current_heading = matched.group(2).strip()
        current_heading_line = index
    if any(line.strip() for line in lines[current_start:]):
        sections.append((current_start, len(lines), current_heading, current_heading_line))
    if not sections:
        sections.append((start, len(lines), current_heading, start))

    chunks: List[AuthorityChunk] = []
    occurrences: Dict[str, int] = {}
    for section_start, section_end, heading, heading_line in sections:
        normalized_heading = _normalized(heading) or "document"
        occurrence = occurrences.get(normalized_heading, 0)
        occurrences[normalized_heading] = occurrence + 1
        stable_key = "{}\0{}\0{}\0{}".format(
            item["item_id"], item["authority_path"], normalized_heading, occurrence
        )
        heading_id = "heading_" + hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:32]
        content_start = section_start
        if section_start == heading_line and HEADING.match(lines[section_start]):
            content_start += 1
        for segment_index, (segment_start, segment_end, segment_text) in enumerate(
            _section_segments(
                lines,
                content_start=content_start,
                section_end=section_end,
                heading=heading,
                fallback_line=heading_line + 1,
            )
        ):
            segment_digest = hashlib.sha256(
                _normalized(segment_text).encode("utf-8")
            ).hexdigest()
            segment_key = "{}\0segment:{}\0{}\0{}:{}".format(
                heading_id,
                segment_index,
                segment_digest,
                segment_start,
                segment_end,
            )
            chunk_id = "chunk_" + hashlib.sha256(segment_key.encode("utf-8")).hexdigest()[:32]
            chunks.append(
                AuthorityChunk(
                    heading_id=heading_id,
                    chunk_id=chunk_id,
                    item_id=str(item["item_id"]),
                    ordinal=len(chunks),
                    segment_index=segment_index,
                    segment_digest=segment_digest,
                    heading=heading,
                    start_line=segment_start,
                    end_line=segment_end,
                    text=segment_text,
                )
            )
    return chunks


class GovernedHybridRetrieval:
    """Rebuildable candidate index whose results are reopened from Git authority."""

    def __init__(
        self,
        *,
        authority: MemoryProjection,
        index_path: Path,
        embedding: Optional[Any] = None,
    ) -> None:
        self.authority = authority
        self.index_path = Path(index_path).resolve(strict=False)
        self.embedding = embedding

    def build(
        self,
        revision: str = "HEAD",
        *,
        context: Mapping[str, Any] | RecallPolicy | None = None,
        now: Optional[datetime] = None,
    ) -> Mapping[str, Any]:
        policy = parse_recall_policy(context)
        governance_context = policy.to_mapping()
        policy_digest = policy.digest()
        source_revision = self.authority._revision(revision)
        items, _tombstones = self.authority._committed_state(source_revision)
        if now is not None:
            if now.tzinfo is None:
                raise RecallPolicyError("hybrid build time must be timezone-aware")
            supplied = now.astimezone(timezone.utc)
            if supplied != policy.as_of:
                raise RecallPolicyError(
                    "hybrid build time must match RecallPolicy.as_of"
                )
        governance_trace = _index_admission_trace(
            items,
            stage="pre_embedding" if self.embedding is not None else "pre_index",
        )
        eligibility = {
            str(item["id"]): item["result"] == "eligible"
            for item in governance_trace
        }
        governed_items = [
            item for item in items if eligibility.get(str(item["item_id"])) is True
        ]
        filtered_item_ids = sorted(
            str(item["item_id"]) for item in items
            if eligibility.get(str(item["item_id"])) is not True
        )
        filter_stage = "pre_index"
        indexed_item_ids = sorted(str(item["item_id"]) for item in governed_items)
        context_digest = hashlib.sha256(
            json.dumps(
                governance_context, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".agent-memory-retrieval-", dir=str(self.index_path.parent)
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        chunk_count = 0
        try:
            connection = sqlite3.connect(str(temporary))
            try:
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                connection.execute(
                    "CREATE TABLE candidates (chunk_id TEXT PRIMARY KEY, item_id TEXT NOT NULL, ordinal INTEGER NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE lexical (lane TEXT NOT NULL, feature_hash TEXT NOT NULL, chunk_id TEXT NOT NULL, "
                    "weight INTEGER NOT NULL, PRIMARY KEY (lane, feature_hash, chunk_id))"
                )
                connection.execute("CREATE INDEX lexical_by_chunk ON lexical(chunk_id)")
                connection.execute(
                    "CREATE TABLE semantic (chunk_id TEXT PRIMARY KEY, vector BLOB NOT NULL)"
                )
                built_chunks: List[AuthorityChunk] = []
                for item in governed_items:
                    for chunk in _chunks(item):
                        chunk_count += 1
                        built_chunks.append(chunk)
                        connection.execute(
                            "INSERT INTO candidates VALUES (?, ?, ?)",
                            (chunk.chunk_id, chunk.item_id, chunk.ordinal),
                        )
                        lexical_text = (
                            chunk.heading + "\n" + chunk.text
                            if chunk.segment_index == 0
                            else chunk.text
                        )
                        for feature, count in _lexical_features(lexical_text).items():
                            width = int(feature[3]) if feature.startswith("cjk") else 2
                            # Repetition is evidence of presence, not unlimited
                            # relevance. Saturation prevents a repeated common
                            # fragment from exhausting the candidate budget.
                            weight = min(count, 3) * width
                            connection.execute(
                                "INSERT INTO lexical VALUES (?, ?, ?, ?)",
                                ("lexical", _feature_hash("body", feature), chunk.chunk_id, weight),
                            )
                        if chunk.segment_index == 0:
                            exact_features = {
                                "exact_path": _normalized(str(item["authority_path"])),
                                "exact_name": _normalized(Path(str(item["authority_path"])).name),
                                "exact_title": _normalized(chunk.heading),
                            }
                            for lane, feature in exact_features.items():
                                if feature:
                                    connection.execute(
                                        "INSERT INTO lexical VALUES (?, ?, ?, ?)",
                                        (lane, _feature_hash(lane, feature), chunk.chunk_id, 1),
                                    )
                semantic_status = "degraded"
                semantic_reason = "embedding_unavailable"
                semantic_description: Mapping[str, Any] = {}
                if self.embedding is not None:
                    try:
                        semantic_description = self.embedding.describe()
                        dimension = semantic_description.get("dimension")
                        if semantic_description.get("status") != "ready" or not isinstance(dimension, int) or dimension <= 0:
                            raise ValueError("embedding description is not ready")
                        for offset in range(0, len(built_chunks), 128):
                            batch = built_chunks[offset : offset + 128]
                            vectors = self.embedding.embed([_semantic_text(chunk) for chunk in batch])
                            if len(vectors) != len(batch):
                                raise ValueError("embedding batch cardinality mismatch")
                            for chunk, vector in zip(batch, vectors):
                                if len(vector) != dimension:
                                    raise ValueError("embedding vector dimension mismatch")
                                connection.execute(
                                    "INSERT INTO semantic VALUES (?, ?)",
                                    (chunk.chunk_id, _vector_bytes(vector)),
                                )
                        semantic_status = "ready"
                        semantic_reason = ""
                    except Exception as error:
                        connection.execute("DELETE FROM semantic")
                        semantic_status = "degraded"
                        semantic_reason = "embedding_unavailable:{}".format(type(error).__name__)
                metadata = {
                    "schema_version": str(INDEX_SCHEMA_VERSION),
                    "source_revision": source_revision,
                    "semantic_status": semantic_status,
                    "semantic_reason": semantic_reason,
                    "semantic_description": json.dumps(semantic_description, sort_keys=True, separators=(",", ":")),
                    "governance_context_sha256": context_digest,
                    "recall_policy_sha256": policy_digest,
                    "recall_policy_binding": "build_audit_only",
                    "index_admission_policy": INDEX_ADMISSION_POLICY,
                    "governance_trace": json.dumps(governance_trace, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    "indexed_item_ids": json.dumps(indexed_item_ids, separators=(",", ":")),
                    "filtered_item_ids": json.dumps(filtered_item_ids, separators=(",", ":")),
                    "filter_stage": filter_stage,
                }
                connection.executemany("INSERT INTO metadata VALUES (?, ?)", sorted(metadata.items()))
                connection.commit()
            finally:
                connection.close()
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.index_path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return {
            "schema_version": 1,
            "status": "built",
            "source_revision": source_revision,
            "recall_policy_sha256": policy_digest,
            "chunk_count": chunk_count,
            "indexed_item_ids": indexed_item_ids,
            "filtered_item_ids": filtered_item_ids,
            "governance_trace": governance_trace,
            "filter_owner": "production",
            "filter_stage": filter_stage,
            "adapter_prefilter_applied": False,
            "semantic": {
                "status": semantic_status,
                "reason": semantic_reason,
                "description": dict(semantic_description),
            },
        }

    def _connection(self) -> sqlite3.Connection:
        if not self.index_path.is_file() or self.index_path.is_symlink():
            raise RuntimeError("retrieval_index_unavailable")
        connection = sqlite3.connect("file:{}?mode=ro".format(self.index_path), uri=True)
        connection.row_factory = sqlite3.Row
        return connection

    def recall(
        self,
        query: str,
        *,
        context: Mapping[str, Any] | RecallPolicy | None = None,
        limit: int = 5,
        aliases: Optional[Mapping[str, Sequence[str]]] = None,
        governance_trace_stage: Optional[str] = None,
        request_binding: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        try:
            policy = parse_recall_policy(context)
        except RecallPolicyError:
            return {
                "schema_version": 1,
                "status": "abstain",
                "reason": "recall_policy_invalid",
                "matches": [],
            }
        context = policy.to_mapping()
        if request_binding is not None and not validate_recall_request_binding(
            request_binding,
            query=query,
            policy=policy,
        ):
            return {
                "schema_version": 1,
                "status": "abstain",
                "reason": "recall_request_binding_invalid",
                "matches": [],
            }
        if not isinstance(query, str) or not query.strip() or limit <= 0 or limit > 20:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": []}
        # Explicit requests for a retired/deleted memory are not ordinary
        # retrieval.  Returning a current rule can violate the requested
        # no-memory semantics, while returning an old candidate would bypass
        # tombstone governance.  Fail closed before any index lookup.
        if RETIRED_MEMORY_QUERY.search(query):
            return {
                "schema_version": 1,
                "status": "abstain",
                "reason": "retired_memory_query",
                "matches": [],
            }
        try:
            if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
                return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_too_large"], "matches": []}
        except UnicodeEncodeError:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": []}
        query_features = _lexical_features(query)
        alias_terms: List[str] = default_alias_terms(query)
        for expansion in alias_terms:
            query_features.update(_lexical_features(expansion))
        normalized_query = _normalized(query)
        exact_query_terms = _exact_query_terms(query)
        if aliases:
            for alias_query, expansions in aliases.items():
                if _normalized(alias_query) != normalized_query:
                    continue
                for expansion in expansions:
                    if isinstance(expansion, str) and expansion.strip():
                        alias_terms.append(expansion)
                        query_features.update(_lexical_features(expansion))
        if not query_features:
            return {"schema_version": 1, "status": "no_safe_match", "reason_codes": ["query_invalid"], "matches": []}

        current_revision = self.authority._revision("HEAD")
        connection = self._connection()
        try:
            metadata = dict(connection.execute("SELECT key, value FROM metadata"))
            if metadata.get("schema_version") != str(INDEX_SCHEMA_VERSION):
                return {
                    "schema_version": 1,
                    "status": "abstain",
                    "reason": "index_schema_stale",
                    "matches": [],
                }
            if metadata.get("source_revision") != current_revision:
                return {"schema_version": 1, "status": "abstain", "reason": "source_stale", "matches": []}
            if metadata.get("index_admission_policy") != INDEX_ADMISSION_POLICY:
                return {
                    "schema_version": 1,
                    "status": "abstain",
                    "reason": "index_admission_stale",
                    "matches": [],
                }
            items, _tombstones = self.authority._committed_state(current_revision)
            now = parse_time(str(context.get("as_of"))) if context.get("as_of") else datetime.now(timezone.utc)
            if now is None:
                now = datetime.now(timezone.utc)
            eligible_by_id = {
                str(item["item_id"]): item
                for item in items
                if self.authority._eligible(item, context, now)[0]
            }
            all_item_ids = {str(item["item_id"]) for item in items}
            filtered_item_ids = sorted(all_item_ids - set(eligible_by_id))
            indexed_item_ids = sorted(
                json.loads(metadata.get("indexed_item_ids", "[]"))
            )
            governance_trace = self.authority._governance_trace(
                items,
                context,
                now,
                stage="pre_embedding" if self.embedding is not None else "pre_index",
            )
            if governance_trace_stage is not None:
                if governance_trace_stage not in {"pre_index", "pre_embedding", "host_injection"}:
                    raise ValueError("unsupported governance trace stage")
                governance_trace = self.authority._governance_trace(
                    items, context, now, stage=governance_trace_stage
                )
            hashes = [_feature_hash("body", feature) for feature in query_features]
            placeholders = ",".join("?" for _value in hashes)
            eligible_ids = sorted(eligible_by_id)
            eligible_placeholders = ",".join("?" for _value in eligible_ids)
            eligibility_clause = (
                " AND c.item_id IN ({})".format(eligible_placeholders)
                if eligible_ids else " AND 0"
            )
            lexical_rows = list(connection.execute(
                "SELECT c.chunk_id, c.item_id, SUM(l.weight) AS score "
                "FROM lexical l JOIN candidates c ON c.chunk_id = l.chunk_id "
                "WHERE l.lane = 'lexical' AND l.feature_hash IN ({}){} GROUP BY c.chunk_id, c.item_id "
                "ORDER BY score DESC, c.chunk_id ASC LIMIT ?".format(placeholders, eligibility_clause),
                (*hashes, *eligible_ids, min(limit * 20, MAX_CANDIDATES)),
            ))
            exact_rows: List[sqlite3.Row] = []
            exact_lanes_by_chunk: Dict[str, List[str]] = {}
            for exact_lane in ("exact_path", "exact_name", "exact_title"):
                for exact_query in exact_query_terms[exact_lane]:
                    for row in connection.execute(
                        "SELECT c.chunk_id, c.item_id, l.weight AS score "
                        "FROM lexical l JOIN candidates c ON c.chunk_id = l.chunk_id "
                        "WHERE l.lane = ? AND l.feature_hash = ?{} ORDER BY c.chunk_id ASC LIMIT ?".format(
                            eligibility_clause
                        ),
                        (
                            exact_lane,
                            _feature_hash(exact_lane, exact_query),
                            *eligible_ids,
                            min(limit * 20, MAX_CANDIDATES),
                        ),
                    ):
                        exact_rows.append(row)
                        exact_lanes_by_chunk.setdefault(str(row["chunk_id"]), []).append(exact_lane)

            semantic_rows: List[Dict[str, Any]] = []
            semantic_compared_item_ids: set[str] = set()
            semantic_query: Optional[List[float]] = None
            semantic_status = metadata.get("semantic_status", "degraded")
            semantic_reason = metadata.get("semantic_reason", "embedding_unavailable")
            semantic_dimension = 0
            semantic_threshold = SEMANTIC_THRESHOLD
            if semantic_status == "ready" and self.embedding is not None:
                try:
                    stored_description = json.loads(metadata.get("semantic_description", "{}"))
                    if not isinstance(stored_description, dict):
                        raise ValueError("embedding manifest is not an object")
                    description = self.embedding.describe()
                    mismatches = embedding_manifest_mismatches(stored_description, description)
                    if mismatches:
                        semantic_status = "degraded"
                        semantic_reason = (
                            "embedding_fingerprint_mismatch"
                            if mismatches == ["fingerprint"]
                            else "embedding_manifest_mismatch:" + ",".join(mismatches)
                        )
                        description = {}
                    if semantic_status != "ready":
                        raise RuntimeError(semantic_reason)
                    semantic_dimension = int(description["dimension"])
                    configured_threshold = description.get(
                        "similarity_threshold", SEMANTIC_THRESHOLD
                    )
                    if (
                        not isinstance(configured_threshold, (int, float))
                        or isinstance(configured_threshold, bool)
                        or not -1.0 <= float(configured_threshold) <= 1.0
                    ):
                        raise ValueError("embedding similarity threshold is invalid")
                    semantic_threshold = float(configured_threshold)
                    semantic_query = self.embedding.embed([query])[0]
                    for row in connection.execute(
                        "SELECT c.chunk_id, c.item_id, s.vector FROM semantic s "
                        "JOIN candidates c ON c.chunk_id = s.chunk_id ORDER BY c.chunk_id ASC"
                    ):
                        # Scope/lifecycle/tombstone/time filtering is a
                        # production retrieval responsibility.  Apply it
                        # before vector comparison so an ineligible candidate
                        # cannot consume rank budget or appear in semantic
                        # evidence merely because it exists in a rebuildable
                        # projection.
                        if str(row["item_id"]) not in eligible_by_id:
                            continue
                        semantic_compared_item_ids.add(str(row["item_id"]))
                        similarity = _cosine(
                            semantic_query,
                            _vector_from_bytes(row["vector"], semantic_dimension),
                        )
                        if similarity >= semantic_threshold:
                            semantic_rows.append(
                                {
                                    "chunk_id": row["chunk_id"],
                                    "item_id": row["item_id"],
                                    "score": similarity,
                                }
                            )
                    semantic_rows.sort(key=lambda value: (-float(value["score"]), str(value["chunk_id"])))
                    del semantic_rows[MAX_CANDIDATES:]
                except Exception as error:
                    semantic_rows = []
                    semantic_query = None
                    if semantic_status == "ready":
                        semantic_status = "degraded"
                        semantic_reason = "embedding_unavailable_at_recall:{}".format(type(error).__name__)
            elif semantic_status == "ready":
                semantic_status = "degraded"
                semantic_reason = "embedding_unavailable_at_recall"

            ranked_channels: Dict[str, Dict[str, int]] = {}
            row_by_chunk: Dict[str, Any] = {}
            for channel, ranked_rows in (
                ("exact", exact_rows),
                ("lexical", lexical_rows),
                ("semantic", semantic_rows),
            ):
                seen: set[str] = set()
                rank = 0
                for row in ranked_rows:
                    chunk_id = str(row["chunk_id"])
                    row_by_chunk.setdefault(chunk_id, row)
                    if chunk_id in seen:
                        continue
                    seen.add(chunk_id)
                    rank += 1
                    ranked_channels.setdefault(chunk_id, {})[channel] = rank
            query_normalized = _normalized(query)
            matches: List[Dict[str, Any]] = []
            reasons: List[str] = []
            for chunk_id, row in row_by_chunk.items():
                item = eligible_by_id.get(str(row["item_id"]))
                if item is None:
                    reasons.append("candidate_filtered")
                    continue
                authoritative_chunks = {chunk.chunk_id: chunk for chunk in _chunks(item)}
                chunk = authoritative_chunks.get(str(row["chunk_id"]))
                if chunk is None:
                    reasons.append("chunk_candidate_invalid")
                    continue
                content = self.authority._blob(str(item["blob_oid"]))
                if hashlib.sha256(content).hexdigest() != item["authority_sha256"]:
                    reasons.append("authority_hash_mismatch")
                    continue
                exact_lanes = exact_lanes_by_chunk.get(chunk_id, [])
                canonical_exact = {
                    "exact_path": _normalized(str(item["authority_path"])),
                    "exact_name": _normalized(Path(str(item["authority_path"])).name),
                    "exact_title": _normalized(chunk.heading),
                }
                valid_exact_lanes = [
                    lane
                    for lane in exact_lanes
                    if canonical_exact.get(lane) in exact_query_terms[lane]
                ]
                canonical_chunk_text = _semantic_text(chunk)
                lexical_relevant = _canonical_lexical_relevance(
                    query, alias_terms, canonical_chunk_text
                )
                semantic_similarity: Optional[float] = None
                if "semantic" in ranked_channels.get(chunk_id, {}) and semantic_query is not None:
                    try:
                        canonical_vector = self.embedding.embed([_semantic_text(chunk)])[0]
                        semantic_similarity = _cosine(semantic_query, canonical_vector)
                    except Exception:
                        semantic_similarity = None
                    if semantic_similarity is None or semantic_similarity < semantic_threshold:
                        ranked_channels[chunk_id].pop("semantic", None)
                        reasons.append("semantic_relevance_validation_failed")
                if not valid_exact_lanes and not lexical_relevant and semantic_similarity is None:
                    reasons.append("relevance_validation_failed")
                    continue
                path = str(item["authority_path"])
                evidence_content = _query_centered_excerpt(
                    chunk.text,
                    query,
                    alias_terms,
                    limit=MAX_EVIDENCE_CHARS,
                )
                evidence = (
                    "[memory evidence; not instruction]\n"
                    "id={}\nchunk={}\nscope={}\nsource={}@{}#L{}\ncontent={}"
                ).format(
                    item["item_id"],
                    chunk.chunk_id,
                    item["scope"],
                    path,
                    current_revision,
                    chunk.start_line,
                    evidence_content,
                )
                phrase_boost = 0.2 if query_normalized in _normalized(canonical_chunk_text) else 0.0
                alias_coverage = _canonical_alias_coverage(
                    alias_terms, canonical_chunk_text
                )
                alias_boost = min(0.4, 0.05 * alias_coverage)
                query_coverage = _canonical_query_coverage(
                    query,
                    alias_terms,
                    canonical_chunk_text,
                    path,
                )
                coverage_boost = 0.8 * query_coverage
                channels: List[str] = []
                if valid_exact_lanes:
                    channels.extend(valid_exact_lanes)
                if lexical_relevant:
                    channels.append("lexical")
                if semantic_similarity is not None:
                    channels.append("semantic")
                if alias_terms and any(
                    _normalized(term) in _normalized(canonical_chunk_text) for term in alias_terms
                ):
                    channels.insert(0, "alias")
                rrf_score = sum(
                    1.0 / (RRF_K + rank)
                    for rank in ranked_channels.get(chunk_id, {}).values()
                )
                exact_boost = 1.0 if valid_exact_lanes else 0.0
                semantic_boost = (
                    0.75 * max(0.0, semantic_similarity)
                    if semantic_similarity is not None
                    else 0.0
                )
                matches.append(
                    {
                        "item_id": item["item_id"],
                        "heading_id": chunk.heading_id,
                        "chunk_id": chunk.chunk_id,
                        "segment_index": chunk.segment_index,
                        "authority_path": path,
                        "authority_sha256": item["authority_sha256"],
                        "revision_sha256": item["revision_sha256"],
                        "content_sha256": item["content_sha256"],
                        "source_revision": current_revision,
                        "source_ref": "{}@{}#L{}".format(path, current_revision, chunk.start_line),
                        "scope": item["scope"],
                        "applies_to": item["applies_to"],
                        "lifecycle": item["lifecycle"],
                        "valid_from": item["valid_from"],
                        "valid_to": item["valid_to"],
                        "trust_class": item["trust_class"],
                        "authorization_state": item["authorization_state"],
                        "provenance_trust": item["provenance_trust"],
                        "privacy_class": item["privacy_class"],
                        "deleted": bool(item["deleted"]),
                        "tombstone": bool(item["tombstoned"]),
                        "heading": chunk.heading,
                        "canonical_reopened": True,
                        "retrieval_channels": list(dict.fromkeys(channels)),
                        "channel_ranks": dict(ranked_channels.get(chunk_id, {})),
                        "rrf_k": RRF_K,
                        "rrf_score": rrf_score,
                        "semantic_similarity": semantic_similarity,
                        "query_coverage": query_coverage,
                        "matched_query_terms": _matched_query_terms(
                            query,
                            "{}\n{}\n{}".format(
                                chunk.heading, chunk.text, item["authority_path"]
                            ),
                        ),
                        "score": (
                            exact_boost
                            + phrase_boost
                            + alias_boost
                            + coverage_boost
                            + semantic_boost
                            + rrf_score
                        ),
                        "evidence": evidence,
                    }
                )
            matches.sort(key=lambda value: (-float(value["score"]), str(value["chunk_id"])))
            mode = "hybrid" if semantic_status == "ready" else "lexical"
            return {
                "schema_version": 1,
                "status": "hit" if matches else "no_safe_match",
                "source_revision": current_revision,
                "retrieval_mode": mode,
                "semantic": {
                    "status": semantic_status,
                    "reason": semantic_reason,
                    "dimension": semantic_dimension or None,
                },
                "reason_codes": sorted(set(reasons)),
                "production_filter": {
                    "filter_owner": "production",
                    "filter_stage": "pre_index",
                    "adapter_prefilter_applied": False,
                    "indexed_item_ids": indexed_item_ids,
                    "filtered_item_ids": filtered_item_ids,
                    "embedded_item_ids": (
                        indexed_item_ids
                        if metadata.get("semantic_status") == "ready"
                        else []
                    ),
                    "governance_trace": governance_trace,
                },
                "matches": matches[:limit],
            }
        finally:
            connection.close()
