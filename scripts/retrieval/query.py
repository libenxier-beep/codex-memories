from __future__ import annotations

import re
import unicodedata
from typing import Iterable


ASCII_WORD = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def normalize_query_text(value: object) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    text = text.translate(
        str.maketrans(
            {
                "‐": "-",
                "‑": "-",
                "‒": "-",
                "–": "-",
                "—": "-",
                "﹣": "-",
                "−": "-",
                "\\": "/",
            }
        )
    )
    text = re.sub(r"\s*/\s*", "/", text)
    return re.sub(r"\s+", " ", text).strip()


def _contains_any(normalized: str, values: Iterable[str]) -> bool:
    return any(value in normalized for value in values)


def _phrase_is_explicitly_negated(normalized: str, phrase: str) -> bool:
    escaped = re.escape(phrase)
    target = (
        rf"(?<![a-z0-9_]){escaped}(?![a-z0-9_])"
        if phrase.isascii()
        else escaped
    )
    return bool(
        re.search(
            rf"\b(?:do\s+not|don't|never|avoid|exclude|without)\s+"
            rf"(?:(?:want|need|use|using|include|including|choose|select|adopt)\s+)?"
            rf"(?:the\s+)?{target}",
            normalized,
        )
        or re.search(rf"\bno\s+{target}", normalized)
        or re.search(
            rf"{target}\s+(?:is|are)\s+(?:not|never)\s+"
            rf"(?:required|needed|wanted|used|allowed|selected|adopted)\b",
            normalized,
        )
        or re.search(
            rf"(?<![要用需])(?:不要|不用|不使用|无需|不需要|别用|禁止使用)"
            rf"[^，。,.!?；;]{{0,4}}{target}",
            normalized,
        )
    )


def english_lexical_variants(token: str) -> list[str]:
    irregular = {
        "led": "lead",
        "ran": "run",
        "written": "write",
        "wrote": "write",
    }
    if token in irregular:
        return [irregular[token]]
    if not token.isascii() or not token.isalpha() or len(token) < 4:
        return []
    variants: list[str] = []
    if token.endswith("ies") and len(token) > 4:
        variants.append(token[:-3] + "y")
    elif token.endswith("ing") and len(token) > 5:
        stem = token[:-3]
        variants.append(stem[:-1] if len(stem) > 3 and stem[-1:] == stem[-2:-1] else stem)
    elif token.endswith("ed") and len(token) > 4:
        stem = token[:-2]
        variants.append(stem[:-1] if len(stem) > 3 and stem[-1:] == stem[-2:-1] else stem)
        if stem.endswith(("c", "g", "r", "s", "v")):
            variants.append(stem + "e")
    elif token.endswith("es") and len(token) > 4:
        variants.append(
            token[:-2]
            if token.endswith(("ches", "shes", "sses", "xes", "zes"))
            else token[:-1]
        )
    elif token.endswith("s") and not token.endswith(("ss", "us", "is")):
        variants.append(token[:-1])
    return list(dict.fromkeys(variant for variant in variants if len(variant) >= 3))


def detect_context_concepts(value: object) -> list[str]:
    """Return high-confidence governed context concepts, never query-specific IDs."""
    normalized = normalize_query_text(value)
    words = set(ASCII_WORD.findall(normalized))
    concepts: list[str] = []

    mcp_aliases = ("mcp", "model context protocol", "模型上下文协议")
    explicit_mcp = _contains_any(normalized, mcp_aliases[1:]) or "mcp" in words
    mcp_negated = any(
        alias in normalized and _phrase_is_explicitly_negated(normalized, alias)
        for alias in mcp_aliases
    )
    english_tool = bool(words & {"tool", "tools"})
    english_mcp_facets = len(
        words
        & {
            "authorization",
            "capabilities",
            "capability",
            "interoperability",
            "protocol",
            "resource",
            "resources",
        }
    )
    chinese_tool = "工具" in normalized
    chinese_mcp_facets = sum(
        signal in normalized
        for signal in ("资源", "授权", "协议", "身份", "能力")
    )
    if not mcp_negated and (
        explicit_mcp
        or (english_tool and english_mcp_facets >= 2)
        or (chinese_tool and chinese_mcp_facets >= 2)
    ):
        concepts.append("mcp")

    explicit_agent_memory = _contains_any(
        normalized,
        (
            "agent memory",
            "conversation memory",
            "durable memory",
            "long-term memory",
            "long term memory",
            "persistent memory",
            "智能体长期记忆",
            "代理长期记忆",
        ),
    )
    english_agent = bool(words & {"agent", "agents", "assistant", "assistants"})
    english_persistence = bool(
        words & {"durable", "longterm", "persist", "persistent", "persisted", "persistence"}
    )
    english_memory_object = bool(
        words & {"conversation", "conversations", "fact", "facts", "memory", "memories"}
    )
    english_retrieval = bool(words & {"recall", "remember", "retrieve", "retrieved", "retrieval"})
    chinese_agent = "智能体" in normalized or "代理" in normalized
    chinese_persistence = _contains_any(normalized, ("长期", "持久", "跨会话", "沉淀"))
    chinese_memory_object = _contains_any(normalized, ("事实", "记忆", "对话"))
    chinese_retrieval = _contains_any(normalized, ("找回", "检索", "召回", "记住"))
    if (
        explicit_agent_memory
        or (english_agent and english_persistence and english_memory_object and english_retrieval)
        or (chinese_agent and chinese_persistence and chinese_memory_object and chinese_retrieval)
    ):
        concepts.append("agent_memory_knowledge_bases")
    return concepts


def detect_temporal_mode(value: object) -> str:
    normalized = normalize_query_text(value)
    words = set(ASCII_WORD.findall(normalized))
    historical = bool(
        words
        & {
            "before",
            "earlier",
            "former",
            "formerly",
            "historical",
            "history",
            "originally",
            "previous",
            "previously",
            "prior",
        }
    ) or _contains_any(normalized, ("曾经", "曾", "历史", "之前", "当时", "原来", "最初"))
    current = bool(words & {"current", "currently", "latest", "now", "today"}) or _contains_any(
        normalized,
        ("当前", "现在", "最新", "现行", "目前"),
    )
    if historical and current:
        return "timeline"
    if historical:
        return "historical"
    return "current"


def detect_multihop_relation_intent(value: object) -> bool:
    """Recognize compositional relation questions without benchmark-specific phrases."""
    normalized = normalize_query_text(value)
    words = set(ASCII_WORD.findall(normalized))
    explicitly_negated = bool(
        re.search(
            r"\b(?:do\s+not|don't|never|avoid)\s+"
            r"(?:follow|trace|traverse|expand|infer|resolve|explore)\b",
            normalized,
        )
        or re.search(
            r"(?<![要用需])(?:不要|不用|无需|不需要|别|禁止)"
            r"(?:再)?(?:追溯|多跳|展开|遍历|推断|关联)",
            normalized,
        )
    )
    if explicitly_negated:
        return False
    english_families = (
        {"author", "authored", "authors", "write", "writes", "wrote", "written"},
        {"belong", "belonged", "belongs", "own", "owned", "owner", "owners", "owns"},
        {"create", "created", "creates", "found", "founded", "founds"},
        {"depend", "depended", "depends", "require", "required", "requires"},
        {"lead", "leader", "leaders", "leads", "led"},
        {"manage", "managed", "manager", "managers", "manages"},
        {"member", "members", "report", "reported", "reports"},
        {"use", "used", "uses"},
    )
    english_relations = sum(bool(words & family) for family in english_families)
    chinese_relations = sum(
        signal in normalized
        for signal in (
            "作者",
            "创建",
            "依赖",
            "使用",
            "属于",
            "拥有",
            "负责人",
            "负责",
            "领导",
            "管理",
            "成员",
            "汇报",
        )
    )
    explicit_chain = _contains_any(
        normalized,
        (
            "关系链",
            "多跳",
            "关联路径",
            "追溯",
            "relation chain",
            "relationship chain",
            "multi-hop",
            "multihop",
        ),
    )
    return explicit_chain or english_relations + chinese_relations >= 2

