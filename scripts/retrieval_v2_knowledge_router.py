#!/usr/bin/env python3
"""Route one query across governed Work and Personal Knowledge collections."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tempfile
import unicodedata
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Iterator, Optional

from retrieval.query import detect_context_concepts


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = Path("knowledge_collections.registry.json")
EVAL_PATH = Path("evals/knowledge_router_cases.csv")
MAX_SNAPSHOT_FILES = 5000
# The private collection retains source-bound audit runs in Git. Keep the
# snapshot bounded while allowing the current governed corpus plus review
# headroom; individual document reads remain exact-blob and policy-gated.
MAX_SNAPSHOT_BYTES = 384 * 1024 * 1024
FORBIDDEN_COLLECTION_FRAGMENTS = ("personal_memories", "personal-memory", "personal memory")
PRIVATE_STORE_SIGNALS = (
    "personal_memories",
    "personal-memories",
)
PRIVATE_DIRECT_SIGNALS = (
    "你记得我什么",
    "关于我的记忆",
    "读取我的 personal memories",
    "read my personal memories",
)
PRIVATE_MEMORY_LABEL_SIGNALS = (
    "personal memories",
    "personal memory",
    "personal-memory",
    "个人记忆库",
    "个人记忆",
    "私人档案",
    "个人档案",
    "身份事实",
    "private profile",
    "identity facts",
)
PRIVATE_MEMORY_ACCESS_SIGNALS = (
    "读取",
    "获取",
    "检索",
    "打开",
    "告诉我",
    "查看",
    "总结",
    "列出",
    "查询",
    "搜索",
    "检查",
    "read",
    "retrieve",
    "open",
    "get",
    "view",
    "show",
    "summarize",
    "list",
    "search",
    "inspect",
)
PRIVATE_MEMORY_USE_SIGNALS = (
    "使用",
    "利用",
    "根据",
    "use",
    "based on",
)
FIRST_PERSON_SIGNALS = (
    "我的",
    "我本人",
    "关于我",
    "my",
    "about me",
)
PRIVATE_FACT_SIGNALS = (
    "体重",
    "体脂",
    "体脂率",
    "病历",
    "诊断",
    "症状",
    "伤病",
    "身体状况",
    "健康状况",
    "检查结果",
    "化验结果",
    "生日",
    "出生日期",
    "家庭住址",
    "家庭地址",
    "住址",
    "职业经历",
    "工作经历",
    "个人履历",
    "身份证",
    "手机号",
    "私人邮箱",
    "家庭关系",
    "人际关系",
    "偏好",
    "个人偏好",
    "姓名",
    "年龄",
    "教育经历",
    "学历",
    "护照号",
    "社会安全号码",
    "银行账号",
    "银行卡号",
    "信用卡号",
    "电子邮箱",
    "邮箱地址",
    "邮箱",
    "联系方式",
    "联系信息",
    "家庭成员",
    "家庭成员关系",
    "账户信息",
    "birthday",
    "date of birth",
    "home address",
    "residential address",
    "work history",
    "employment history",
    "career history",
    "job history",
    "identity record",
    "phone number",
    "personal email",
    "email",
    "email address",
    "ssn",
    "social security number",
    "passport number",
    "passport details",
    "passport",
    "contact information",
    "contact details",
    "family members",
    "family relationships",
    "bank account number",
    "credit card number",
    "preference",
    "preferences",
    "relationship",
    "relationships",
    "education history",
    "education",
    "school history",
    "legal name",
    "full name",
    "age",
    "account information",
    "relationship history",
    "body weight",
    "body fat",
    "medical record",
    "medical history",
    "diagnosis",
    "symptoms",
    "injury history",
    "health status",
    "lab results",
)
GENERIC_PRIVATE_MODELING_SIGNALS = (
    "schema",
    "data model",
    "field design",
    "model fields",
    "数据模型",
    "字段设计",
    "如何设计",
    "怎么建模",
    "分类器",
    "误报",
)
GLOBAL_ROOT_SIGNALS = (
    "knowledge router",
    "collections registry",
    "collection registry",
    "统一知识路由",
    "统一 knowledge router",
)
WORK_ROOT_SIGNALS = (
    "work contexts",
    "work context registry",
    "工作知识库根级",
)
PERSONAL_ROOT_SIGNALS = (
    "personal knowledge",
    "个人知识库根级",
    "个人知识注册表",
)

CURRENT_SOURCE_SAFETY_DIRECT_SIGNALS = (
    "吃什么药",
    "用什么药",
    "用药",
    "药物剂量",
    "医疗诊断",
    "补剂",
    "保健品",
    "该不该吃",
    "值不值得吃",
    "买哪只",
    "买哪个基金",
    "清仓",
    "加仓",
    "现行法律",
    "现行法规",
    "无症状异常值",
    "体检异常值",
    "商业端粒检测",
    "指导个人治疗",
    "二〇二六年能力判断",
    "2026年能力判断",
)
CURRENT_SOURCE_SAFETY_TEMPORAL_SIGNALS = (
    "today",
    "latest",
    "current",
    "currently",
    "live",
    "今天",
    "现在",
    "当前",
    "最新",
    "实时",
    "现行",
    "目前",
)
CURRENT_SOURCE_SAFETY_DYNAMIC_TOPICS = (
    "fund",
    "stock",
    "bond",
    "investment",
    "medicine",
    "symptom",
    "policy",
    "regulation",
    "law",
    "election",
    "exchange rate",
    "interest rate",
    "ai model",
    "基金",
    "股票",
    "债券",
    "投资",
    "药",
    "症状",
    "政策",
    "法规",
    "法律",
    "选举",
    "汇率",
    "利率",
    "人工智能",
    "ai模型",
    "ai 模型",
    "大模型",
)


@dataclass(frozen=True)
class CollectionSource:
    root: Path
    repository: Path
    tree_prefix: Path
    policy: str
    revision: str
    common_dir: Optional[Path] = None

    def public_trace(self) -> dict[str, str]:
        return {"source_policy": self.policy, "source_commit": self.revision}


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", value).casefold()).strip()


def _contains_any(query: str, signals: tuple[str, ...]) -> bool:
    normalized = _normalize(query)
    return any(_normalize(signal) in normalized for signal in signals)


def _contains_signal(normalized: str, signal: str) -> bool:
    normalized_signal = _normalize(signal)
    if not normalized_signal:
        return False
    if all(ord(character) < 128 for character in normalized_signal):
        return (
            re.search(
                rf"(?<![a-z0-9_]){re.escape(normalized_signal)}(?![a-z0-9_])",
                normalized,
            )
            is not None
        )
    return normalized_signal in normalized


def _explicitly_negates_context(query: str, context: dict[str, Any]) -> bool:
    """Detect an explicit exclusion of the context named by a routed trigger."""
    normalized = _normalize(query)
    aliases = [context.get("id"), context.get("title"), *context.get("triggers", [])]
    for value in aliases:
        if not isinstance(value, str):
            continue
        alias = _normalize(value)
        if not alias or len(alias) > 80:
            continue
        escaped = re.escape(alias)
        if all(ord(character) < 128 for character in alias):
            target = rf"(?<![a-z0-9_]){escaped}(?![a-z0-9_])"
        else:
            target = escaped
        if re.search(
            rf"\b(?:do\s+not|don't|never|avoid|exclude|without)\s+"
            rf"(?:(?:want|need|use|using|include|including|choose|select|adopt)\s+)?"
            rf"(?:the\s+)?{target}",
            normalized,
        ):
            return True
        if re.search(rf"\bno\s+{target}", normalized):
            return True
        if re.search(
            rf"{target}\s+(?:is|are)\s+(?:not|never)\s+"
            rf"(?:required|needed|wanted|used|allowed|selected|adopted)\b",
            normalized,
        ):
            return True
        if re.search(
            rf"(?<![要用需])(?:不要|不用|不使用|无需|不需要|别用|禁止使用)"
            rf"[^，。,.!?；;]{{0,4}}{target}",
            normalized,
        ):
            return True
    return False


def _query_fingerprint(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]


def _requires_current_source_safety_floor(query: str) -> bool:
    """Close high-risk freshness gaps left by a narrower pinned router engine."""
    normalized = _normalize(query)
    if any(_contains_signal(normalized, signal) for signal in CURRENT_SOURCE_SAFETY_DIRECT_SIGNALS):
        return True
    temporal = any(
        _contains_signal(normalized, signal) for signal in CURRENT_SOURCE_SAFETY_TEMPORAL_SIGNALS
    )
    dynamic_topic = any(
        _contains_signal(normalized, signal) for signal in CURRENT_SOURCE_SAFETY_DYNAMIC_TOPICS
    )
    return temporal and dynamic_topic


def _regular_file_sha256(root: Path, relative: Path) -> str:
    return hashlib.sha256(_real_file_inside(root, relative).read_bytes()).hexdigest()


def _collection_registry_digest(root: Path) -> str:
    return _regular_file_sha256(root, REGISTRY_PATH)


def _committed_file_sha256(root: Path, revision: str, relative: Path) -> str:
    return hashlib.sha256(_git_regular_blob(root, revision, relative)).hexdigest()


def _is_private_profile_request(query: str) -> bool:
    normalized = _normalize(query)
    if any(_contains_signal(normalized, signal) for signal in PRIVATE_STORE_SIGNALS):
        return True
    if any(_contains_signal(normalized, signal) for signal in PRIVATE_DIRECT_SIGNALS):
        return True
    memory_label = any(_contains_signal(normalized, signal) for signal in PRIVATE_MEMORY_LABEL_SIGNALS)
    memory_access = any(_contains_signal(normalized, signal) for signal in PRIVATE_MEMORY_ACCESS_SIGNALS)
    memory_use = any(_contains_signal(normalized, signal) for signal in PRIVATE_MEMORY_USE_SIGNALS)
    first_person = any(_contains_signal(normalized, signal) for signal in FIRST_PERSON_SIGNALS)
    if memory_label and (memory_access or (first_person and memory_use)):
        return True
    fact_hits = sum(_contains_signal(normalized, signal) for signal in PRIVATE_FACT_SIGNALS)
    possessive_fact = False
    for signal in PRIVATE_FACT_SIGNALS:
        normalized_signal = _normalize(signal)
        if all(ord(character) < 128 for character in normalized_signal):
            if re.search(
                rf"(?<![a-z0-9_])my\s+(?:own\s+)?(?:personal\s+)?{re.escape(normalized_signal)}(?![a-z0-9_])",
                normalized,
            ):
                possessive_fact = True
                break
        elif f"我的{normalized_signal}" in normalized or f"我的 {normalized_signal}" in normalized:
            possessive_fact = True
            break
    generic_modeling = any(
        _contains_signal(normalized, signal) for signal in GENERIC_PRIVATE_MODELING_SIGNALS
    )
    return possessive_fact or (
        first_person and fact_hits > 0 and (not generic_modeling or memory_access)
    )


def _governed_git_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_COMMON_DIR",
        "GIT_REPLACE_REF_BASE",
        "GIT_NAMESPACE",
    ):
        environment.pop(key, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _run_git(cwd: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=_governed_git_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ValueError("cannot resolve governed Git source") from exc
    if result.returncode != 0:
        raise ValueError("cannot resolve governed Git source")
    return result.stdout.strip()


def _run_git_bytes(
    cwd: Path,
    *args: str,
    input_bytes: Optional[bytes] = None,
) -> bytes:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=_governed_git_environment(),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        raise ValueError("cannot read governed Git source") from exc
    if result.returncode != 0:
        raise ValueError("cannot read governed Git source")
    return result.stdout


def _git_regular_blob(
    repository: Path,
    revision: str,
    relative: Path,
) -> bytes:
    safe = _safe_relative(relative.as_posix())
    entry = _run_git(repository, "ls-tree", revision, "--", safe.as_posix())
    match = re.fullmatch(
        rf"(100644|100755) blob ([0-9a-f]{{40}})\t{re.escape(safe.as_posix())}",
        entry,
    )
    if match is None:
        raise ValueError(f"path must be a regular committed file: {safe.as_posix()}")
    return _run_git_bytes(repository, "cat-file", "blob", match.group(2))


def _source_file_bytes(source: CollectionSource, relative: Path) -> bytes:
    safe = _safe_relative(relative.as_posix())
    committed = source.tree_prefix / safe if source.tree_prefix.parts else safe
    return _git_regular_blob(source.repository, source.revision, committed)


@contextmanager
def _materialize_source(source: CollectionSource) -> Iterator[CollectionSource]:
    args = ["ls-tree", "-r", "-z", "-l", source.revision]
    if source.tree_prefix.parts:
        args.extend(["--", source.tree_prefix.as_posix()])
    tree = _run_git_bytes(source.repository, *args)
    entries: list[tuple[Path, str]] = []
    normalized_paths: set[tuple[str, ...]] = set()
    normalized_directories: dict[tuple[str, ...], tuple[str, ...]] = {}
    total_bytes = 0
    for raw_entry in tree.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, object_id, raw_size = metadata.decode("ascii").split()
            size = int(raw_size)
            path_text = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("governed Git tree contains an invalid entry") from exc
        if mode not in {"100644", "100755"} or object_type != "blob" or not re.fullmatch(
            r"[0-9a-f]{40}", object_id
        ) or size < 0:
            raise ValueError("governed Git tree contains a non-regular entry")
        relative = _safe_relative(path_text)
        normalized = tuple(
            unicodedata.normalize("NFC", part).casefold() for part in relative.parts
        )
        for index in range(1, len(relative.parts)):
            normalized_directory = normalized[:index]
            raw_directory = relative.parts[:index]
            previous = normalized_directories.get(normalized_directory)
            if previous is not None and previous != raw_directory:
                raise ValueError("governed Git tree contains colliding directory paths")
            normalized_directories[normalized_directory] = raw_directory
        if normalized in normalized_paths or any(
            existing == normalized[: len(existing)]
            or normalized == existing[: len(normalized)]
            for existing in normalized_paths
        ):
            raise ValueError("governed Git tree contains colliding paths")
        normalized_paths.add(normalized)
        entries.append((relative, object_id))
        total_bytes += size
        if len(entries) > MAX_SNAPSHOT_FILES or total_bytes > MAX_SNAPSHOT_BYTES:
            raise ValueError("governed Git snapshot exceeds its size limit")
    if not entries:
        raise ValueError("governed Git tree is empty")

    batch_input = ("\n".join(object_id for _, object_id in entries) + "\n").encode("ascii")
    batch = io.BytesIO(
        _run_git_bytes(
            source.repository,
            "cat-file",
            "--batch",
            input_bytes=batch_input,
        )
    )
    with tempfile.TemporaryDirectory(prefix="knowledge-route-") as temporary:
        snapshot = Path(temporary)
        for relative, expected_object_id in entries:
            header = batch.readline().rstrip(b"\n")
            try:
                object_id, object_type, raw_size = header.decode("ascii").split(" ")
                size = int(raw_size)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("governed Git blob batch is invalid") from exc
            if (
                object_id != expected_object_id
                or object_type != "blob"
                or size < 0
            ):
                raise ValueError("governed Git blob batch does not match its tree")
            content = batch.read(size)
            if len(content) != size or batch.read(1) != b"\n":
                raise ValueError("governed Git blob batch is truncated")
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        if batch.read(1):
            raise ValueError("governed Git blob batch contains trailing data")
        materialized_root = snapshot / source.tree_prefix if source.tree_prefix.parts else snapshot
        if not materialized_root.is_dir() or materialized_root.is_symlink():
            raise ValueError("governed Git snapshot root is invalid")
        yield replace(source, root=materialized_root)


def _git_revision(root: Path) -> str:
    revision = _run_git(root, "rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("governed Git source has an invalid revision")
    return revision


def _gitlink_revision(root: Path, mount: Path) -> str:
    entry = _run_git(root, "ls-tree", "HEAD", "--", mount.as_posix())
    match = re.fullmatch(
        rf"160000 commit ([0-9a-f]{{40}})\t{re.escape(mount.as_posix())}",
        entry,
    )
    if match is None:
        raise ValueError("collection mount is not an exact parent gitlink")
    return match.group(1)


def _real_worktree_root(path: Path) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise ValueError("candidate worktree is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise ValueError("candidate worktree must be a real non-symlink directory")
    top_level = Path(_run_git(resolved, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if top_level != resolved:
        raise ValueError("candidate path is not a worktree root")
    return resolved


def _git_common_dir(worktree: Path) -> Path:
    raw = Path(_run_git(worktree, "rev-parse", "--git-common-dir"))
    if not raw.is_absolute():
        raw = worktree / raw
    try:
        return raw.resolve(strict=True)
    except (FileNotFoundError, OSError, RuntimeError) as exc:
        raise ValueError("candidate Git common directory is unavailable") from exc


def _resolve_gitlink_source(root: Path, mount: Path) -> CollectionSource:
    expected_revision = _gitlink_revision(root, mount)
    mounted = _real_worktree_root(root / mount)
    common_dir = _git_common_dir(mounted)
    try:
        _run_git(mounted, "cat-file", "-e", f"{expected_revision}^{{commit}}")
    except ValueError as exc:
        raise ValueError("parent gitlink commit is unavailable") from exc
    return CollectionSource(
        root=mounted,
        repository=mounted,
        tree_prefix=Path(),
        policy="gitlink",
        revision=expected_revision,
        common_dir=common_dir,
    )


def _resolve_parent_tree_source(root: Path, mount: Path) -> CollectionSource:
    collection_root = _real_directory_inside(root, mount)
    revision = _git_revision(root)
    return CollectionSource(
        root=collection_root,
        repository=root,
        tree_prefix=mount,
        policy="parent_tree",
        revision=revision,
    )


def resolve_collection_sources(
    root: Path,
    registry: dict[str, Any],
) -> dict[str, CollectionSource]:
    sources: dict[str, CollectionSource] = {}
    for collection in registry["collections"]:
        if collection["status"] != "active" or not collection["searchable"]:
            continue
        sources[collection["id"]] = resolve_collection_source(root, collection)
    return sources


def resolve_collection_source(root: Path, collection: dict[str, Any]) -> CollectionSource:
    mount = _safe_relative(collection["mount"], one_part=True)
    if collection["source_policy"] == "gitlink":
        source = _resolve_gitlink_source(root, mount)
    elif collection["source_policy"] == "parent_tree":
        source = _resolve_parent_tree_source(root, mount)
    else:
        raise ValueError("collection source policy is unsupported")
    entry = _safe_relative(collection["entry_path"])
    registry_path = _safe_relative(collection["registry_path"])
    _source_file_bytes(source, entry)
    _source_file_bytes(source, registry_path)
    return source


def _assert_runtime_sources_stable(
    root: Path,
    registry: dict[str, Any],
    sources: dict[str, CollectionSource],
) -> None:
    collections = {item["id"]: item for item in registry["collections"]}
    for collection_id, source in sources.items():
        collection = collections[collection_id]
        mount = _safe_relative(collection["mount"], one_part=True)
        if source.policy == "gitlink":
            if source.common_dir is None:
                raise ValueError("governed gitlink source lacks its common-directory anchor")
            if _git_common_dir(source.repository) != source.common_dir:
                raise ValueError("governed gitlink repository changed during routing")
            if _gitlink_revision(root, mount) != source.revision:
                raise ValueError("parent gitlink changed during routing")
        elif source.policy == "parent_tree":
            if _git_revision(root) != source.revision:
                raise ValueError("parent-tree revision changed during routing")
        else:
            raise ValueError("collection source policy is unsupported")


def _finalize_result(
    result: dict[str, Any],
    *,
    root: Path,
    parent_revision: str,
    registry: dict[str, Any],
    registry_digest: str,
    sources: dict[str, CollectionSource],
) -> dict[str, Any]:
    if _git_revision(root) != parent_revision:
        raise ValueError("parent knowledge revision changed during routing")
    if _committed_file_sha256(root, parent_revision, REGISTRY_PATH) != registry_digest:
        raise ValueError("parent collection registry changed during routing")
    _assert_runtime_sources_stable(root, registry, sources)
    return result


def _safe_relative(value: object, *, one_part: bool = False) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("path must be a safe repository-relative path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} or ":" in part for part in value.split("/")):
        raise ValueError("path must be a safe repository-relative path")
    if one_part and len(pure.parts) != 1:
        raise ValueError("mount must be a safe repository-relative directory")
    return Path(*pure.parts)


def _real_file_inside(root: Path, relative: Path) -> Path:
    target = root / relative
    try:
        metadata = target.lstat()
        resolved_root = root.resolve(strict=True)
        resolved = target.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"path must resolve inside its collection: {relative.as_posix()}") from exc
    if not stat.S_ISREG(metadata.st_mode) or target.is_symlink():
        raise ValueError(f"path must be a regular non-symlink file: {relative.as_posix()}")
    return resolved


def _real_directory_inside(root: Path, relative: Path) -> Path:
    target = root / relative
    try:
        metadata = target.lstat()
        resolved_root = root.resolve(strict=True)
        resolved = target.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"mount must be a safe repository-relative directory: {relative.as_posix()}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or target.is_symlink():
        raise ValueError(f"mount must be a real non-symlink directory: {relative.as_posix()}")
    return resolved


def load_collection_registry(
    root: Path = ROOT,
    *,
    content: Optional[bytes] = None,
    validate_worktree_paths: bool = True,
) -> dict[str, Any]:
    """Load and validate the parent registry without reading collection registries or bodies."""
    if content is None:
        path = root / REGISTRY_PATH
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ValueError(f"cannot read collection registry: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise ValueError("collection registry must be a regular non-symlink file")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"cannot read collection registry: {exc}") from exc
    try:
        payload = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse collection registry: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("collection registry must use schema_version 1")
    root_fields = {"schema_version", "generated_at", "router_engine", "collections"}
    unexpected_root_fields = set(payload) - root_fields
    if unexpected_root_fields:
        raise ValueError(
            "collection registry contains unsupported fields: "
            + ", ".join(sorted(unexpected_root_fields))
        )
    if not isinstance(payload.get("collections"), list) or not payload["collections"]:
        raise ValueError("collection registry must contain collections")
    generated_at = payload.get("generated_at")
    if not isinstance(generated_at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", generated_at):
        raise ValueError("collection registry generated_at must be an ISO date")
    try:
        date.fromisoformat(generated_at)
    except ValueError as exc:
        raise ValueError("collection registry generated_at must be an ISO date") from exc
    engine = _safe_relative(payload.get("router_engine"))

    seen_ids: set[str] = set()
    seen_mounts: set[str] = set()
    collections_by_mount: dict[str, dict[str, Any]] = {}
    required = {
        "id",
        "mount",
        "entry_path",
        "registry_path",
        "source_policy",
        "summary",
        "triggers",
        "non_triggers",
        "routing_profile",
        "status",
        "searchable",
        "privacy_class",
        "sync_targets",
    }
    for collection in payload["collections"]:
        if not isinstance(collection, dict) or not required.issubset(collection):
            raise ValueError("every collection must contain the required routing fields")
        unexpected_fields = set(collection) - required
        if unexpected_fields:
            raise ValueError(
                "collection contains unsupported fields: "
                + ", ".join(sorted(unexpected_fields))
            )
        collection_id = collection["id"]
        if not isinstance(collection_id, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", collection_id):
            raise ValueError("collection id must be lowercase snake_case")
        try:
            mount = _safe_relative(collection["mount"], one_part=True)
        except ValueError as exc:
            raise ValueError("mount must be a safe repository-relative directory") from exc
        if not re.fullmatch(r"[a-z][a-z0-9_]*", mount.as_posix()):
            raise ValueError("mount must be lowercase snake_case")
        joined_identity = _normalize(f"{collection_id} {mount.as_posix()}")
        if any(fragment in joined_identity for fragment in FORBIDDEN_COLLECTION_FRAGMENTS):
            raise ValueError("private personal memory storage cannot be a knowledge collection")
        if collection_id in seen_ids or mount.as_posix() in seen_mounts:
            raise ValueError("collection ids and mounts must be unique")
        seen_ids.add(collection_id)
        seen_mounts.add(mount.as_posix())
        collections_by_mount[mount.as_posix()] = collection
        collection_root = (
            _real_directory_inside(root, mount) if validate_worktree_paths else None
        )
        try:
            entry = _safe_relative(collection["entry_path"])
        except ValueError as exc:
            raise ValueError(f"{collection_id}: entry path must be safe") from exc
        try:
            registry = _safe_relative(collection["registry_path"])
        except ValueError as exc:
            raise ValueError(f"{collection_id}: registry path must be safe") from exc
        if registry.as_posix() != "contexts.registry.json":
            raise ValueError(f"{collection_id}: registry_path must be contexts.registry.json")
        source_policy = collection["source_policy"]
        if source_policy not in {"gitlink", "parent_tree"}:
            raise ValueError(f"{collection_id}: invalid source policy")
        expected_policy = {"work": "gitlink", "personal_knowledge": "parent_tree"}.get(collection_id)
        if expected_policy is not None and source_policy != expected_policy:
            raise ValueError(f"{collection_id}: source policy must be {expected_policy}")
        if source_policy == "parent_tree" and collection_root is not None:
            _real_file_inside(collection_root, entry)
            _real_file_inside(collection_root, registry)
        if collection["status"] not in {"active", "archived"}:
            raise ValueError(f"{collection_id}: invalid collection status")
        if not isinstance(collection["searchable"], bool):
            raise ValueError(f"{collection_id}: searchable must be boolean")
        if collection["privacy_class"] not in {"portable", "private-local"}:
            raise ValueError(f"{collection_id}: invalid privacy class")
        if not isinstance(collection["summary"], str) or not collection["summary"].strip():
            raise ValueError(f"{collection_id}: summary must be a non-empty string")
        if not isinstance(collection["triggers"], list) or not collection["triggers"] or not all(
            isinstance(item, str) and item.strip() for item in collection["triggers"]
        ):
            raise ValueError(f"{collection_id}: triggers must be non-empty strings")
        if not isinstance(collection["non_triggers"], list) or not all(
            isinstance(item, str) and item.strip() for item in collection["non_triggers"]
        ):
            raise ValueError(f"{collection_id}: non_triggers must be strings")
        if not isinstance(collection["routing_profile"], dict):
            raise ValueError(f"{collection_id}: routing_profile must be an object")
        sync = collection["sync_targets"]
        if (
            not isinstance(sync, dict)
            or set(sync) != {"codex", "github"}
            or not all(isinstance(sync.get(key), bool) for key in ("codex", "github"))
        ):
            raise ValueError(f"{collection_id}: sync_targets must define codex and github booleans")
        if collection["privacy_class"] == "private-local" and sync["github"]:
            raise ValueError(f"{collection_id}: private-local collection cannot sync to GitHub")
    engine_parts = PurePosixPath(engine.as_posix()).parts
    engine_collection = collections_by_mount.get(engine_parts[0]) if engine_parts else None
    if engine_collection is None or engine_collection.get("source_policy") != "gitlink":
        raise ValueError("router_engine must belong to a gitlink collection")
    if len(engine_parts) < 2:
        raise ValueError("router_engine must name a file inside its gitlink collection")
    return payload


def _load_router_engine(
    root: Path,
    registry: dict[str, Any],
    sources: Optional[dict[str, CollectionSource]] = None,
) -> ModuleType:
    if sources is None:
        sources = resolve_collection_sources(root, registry)
    engine_relative = _safe_relative(registry["router_engine"])
    engine_parts = PurePosixPath(engine_relative.as_posix()).parts
    collection = next(
        (
            item
            for item in registry["collections"]
            if item["mount"] == engine_parts[0]
        ),
        None,
    )
    if collection is None or collection["id"] not in sources or len(engine_parts) < 2:
        raise ValueError("cannot resolve the governed router engine source")
    source = sources[collection["id"]]
    engine_relative_in_collection = Path(*engine_parts[1:])
    engine_bytes = _source_file_bytes(source, engine_relative_in_collection)
    try:
        engine_text = engine_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("pinned knowledge router engine must be UTF-8") from exc
    module_name = "pinned_knowledge_router_" + hashlib.sha256(engine_bytes).hexdigest()[:12]
    module = ModuleType(module_name)
    logical_filename = f"{collection['mount']}/{engine_relative_in_collection.as_posix()}@{source.revision}"
    module.__file__ = logical_filename
    try:
        exec(compile(engine_text, logical_filename, "exec"), module.__dict__)
    except Exception as exc:
        raise ValueError("cannot load the pinned knowledge router engine") from exc
    if not callable(getattr(module, "load_registry", None)) or not callable(getattr(module, "route", None)):
        raise ValueError("pinned knowledge router engine lacks the required public seam")
    return module


def _unique_strings(values: Iterator[object] | list[object]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        normalized = _normalize(value)
        if normalized in seen:
            continue
        seen.add(normalized)
        result.append(value)
    return result


def _load_context_registries(
    registry: dict[str, Any],
    sources: dict[str, CollectionSource],
    engine: ModuleType,
) -> dict[str, dict[str, Any]]:
    registries: dict[str, dict[str, Any]] = {}
    validator = getattr(engine, "validate_registry", None)
    if not callable(validator):
        validator = getattr(engine, "_validate_registry", None)
    if not callable(validator):
        raise ValueError("pinned knowledge router engine cannot validate context registries")
    for collection in registry["collections"]:
        collection_id = collection["id"]
        if collection_id not in sources:
            continue
        registry_path = _safe_relative(collection["registry_path"])
        try:
            payload = json.loads(_source_file_bytes(sources[collection_id], registry_path))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("cannot parse a pinned context registry") from exc
        validated = validator(payload)
        if not isinstance(validated, dict):
            raise ValueError("pinned context registry validation returned an invalid value")
        registries[collection_id] = validated
    return registries


def _explicit_context_binding(
    query: str,
    context_registries: dict[str, dict[str, Any]],
) -> tuple[str, str] | None:
    normalized = _normalize(query)
    matches: list[tuple[str, str]] = []
    for collection_id, registry in context_registries.items():
        for context in registry.get("contexts", []):
            if context.get("status") != "active" or not isinstance(context.get("id"), str):
                continue
            context_id = context["id"]
            raw_path = context.get("path")
            directory = PurePosixPath(raw_path).parent.as_posix() if isinstance(raw_path, str) else ""
            if (
                ("_" in context_id and _contains_signal(normalized, context_id))
                or normalized == _normalize(context_id)
                or (
                    directory not in {"", "."}
                    and "_" in directory
                    and _contains_signal(normalized, directory)
                )
            ):
                matches.append((collection_id, context_id))
    unique = list(dict.fromkeys(matches))
    return unique[0] if len(unique) == 1 else None


def _virtual_collection_registry(
    registry: dict[str, Any],
    context_registries: Optional[dict[str, dict[str, Any]]] = None,
) -> dict[str, Any]:
    contexts: list[dict[str, Any]] = []
    context_registries = context_registries or {}
    for collection in registry["collections"]:
        if collection["status"] != "active" or not collection["searchable"]:
            continue
        collection_id = collection["id"]
        path = f"{collection_id}/README.md"
        triggers: list[object] = list(collection["triggers"])
        routing_profile = deepcopy(collection["routing_profile"])
        terms: list[object] = list(routing_profile.get("terms", []))
        boost_groups: list[object] = list(routing_profile.get("boost_groups", []))
        for child in context_registries.get(collection_id, {}).get("contexts", []):
            if child.get("status") != "active":
                continue
            triggers.extend([child.get("id"), child.get("summary"), *child.get("triggers", [])])
            child_profile = child.get("routing_profile", {})
            if isinstance(child_profile, dict):
                terms.extend(child_profile.get("terms", []))
                boost_groups.extend(deepcopy(child_profile.get("boost_groups", [])))
        routing_profile["terms"] = _unique_strings(terms)
        routing_profile["boost_groups"] = boost_groups
        contexts.append(
            {
                "id": collection_id,
                "path": path,
                "summary": collection["summary"],
                "triggers": _unique_strings(triggers),
                "non_triggers": collection["non_triggers"],
                "routing_profile": routing_profile,
                "read_path": [path],
                "deeper_files": [],
                "deeper_routes": [],
                "eval_file": f"{collection_id}/evals.csv",
                "risk_file": f"{collection_id}/risks.md",
                "status": "active",
            }
        )
    return {"schema_version": "2.0", "contexts": contexts}


def _global_root_result(
    query: str,
    root: Path,
    *,
    parent_revision: str,
    registry_digest: str,
) -> dict[str, Any]:
    index_path = Path("memory_index.md")
    index_digest = _committed_file_sha256(root, parent_revision, index_path)
    if _committed_file_sha256(root, parent_revision, REGISTRY_PATH) != registry_digest:
        raise ValueError("parent collection registry changed during routing")
    combined_digest = hashlib.sha256(
        f"{index_digest}\n{registry_digest}\n".encode("utf-8")
    ).hexdigest()
    result = {
        "schema_version": 1,
        "decision": "root",
        "collection_id": None,
        "context_id": None,
        "first_file": index_path.as_posix(),
        "deeper_suggestions": [REGISTRY_PATH.as_posix()],
        "deeper_matches": [],
        "alternatives": [],
        "current_sources_required": False,
        "query_fingerprint": _query_fingerprint(query),
        "reason_codes": ["global_knowledge_maintenance"],
        "trace": {
            "stage": "collection_root",
            "engine_version": "2",
            "source_policy": "parent_tree",
            "source_commit": parent_revision,
            "source_digest": combined_digest,
        },
    }
    if _committed_file_sha256(root, parent_revision, index_path) != index_digest:
        raise ValueError("parent index changed during routing")
    if (
        _committed_file_sha256(root, parent_revision, REGISTRY_PATH) != registry_digest
        or _git_revision(root) != parent_revision
    ):
        raise ValueError("parent collection registry changed during routing")
    return result


def _collection_root_result(
    query: str,
    collection: dict[str, Any],
    *,
    source: CollectionSource,
) -> dict[str, Any]:
    mount = collection["mount"]
    _source_file_bytes(source, _safe_relative(collection["entry_path"]))
    _source_file_bytes(source, _safe_relative(collection["registry_path"]))
    return {
        "schema_version": 1,
        "decision": "root",
        "collection_id": collection["id"],
        "context_id": None,
        "first_file": f"{mount}/{collection['entry_path']}",
        "deeper_suggestions": [f"{mount}/{collection['registry_path']}"],
        "deeper_matches": [],
        "alternatives": [],
        "current_sources_required": False,
        "query_fingerprint": _query_fingerprint(query),
        "reason_codes": ["collection_maintenance"],
        "trace": {
            "stage": "collection_root",
            "engine_version": "2",
            **source.public_trace(),
        },
    }


def _prefix_collection_file(
    source: CollectionSource,
    collection: dict[str, Any],
    raw: object,
) -> str:
    relative = _safe_relative(raw)
    _source_file_bytes(source, relative)
    return f"{collection['mount']}/{relative.as_posix()}"


def _adapt_context_alternatives(
    source: CollectionSource,
    collection: dict[str, Any],
    alternatives: object,
) -> list[dict[str, Any]]:
    if not isinstance(alternatives, list):
        raise ValueError("context alternatives must be an array")
    adapted_alternatives: list[dict[str, Any]] = []
    for alternative in alternatives:
        if not isinstance(alternative, dict):
            raise ValueError("context alternative must be an object")
        adapted = dict(alternative)
        if "path" in adapted:
            adapted["path"] = _prefix_collection_file(source, collection, adapted["path"])
        adapted_alternatives.append(adapted)
    return adapted_alternatives


def _adapt_collection_alternatives(
    sources: dict[str, CollectionSource],
    collections: dict[str, dict[str, Any]],
    alternatives: object,
) -> list[dict[str, Any]]:
    if not isinstance(alternatives, list):
        raise ValueError("collection alternatives must be an array")
    adapted_alternatives: list[dict[str, Any]] = []
    for alternative in alternatives:
        if not isinstance(alternative, dict):
            raise ValueError("collection alternative must be an object")
        collection_id = alternative.get("context_id")
        collection = collections.get(collection_id) if isinstance(collection_id, str) else None
        if collection is None:
            raise ValueError("collection alternative references an unknown collection")
        expected_virtual_path = f"{collection_id}/README.md"
        if alternative.get("path") != expected_virtual_path:
            raise ValueError("collection alternative path does not match the virtual registry")
        adapted = dict(alternative)
        adapted["path"] = _prefix_collection_file(
            sources[collection_id],
            collection,
            collection["entry_path"],
        )
        adapted_alternatives.append(adapted)
    return adapted_alternatives


def _shared_concept_alternatives(
    query: str,
    *,
    context_registries: dict[str, dict[str, Any]],
    collections: dict[str, dict[str, Any]],
    sources: dict[str, CollectionSource],
) -> list[dict[str, Any]]:
    concepts = set(detect_context_concepts(query))
    if not concepts:
        return []
    alternatives: list[dict[str, Any]] = []
    for collection_id, registry in context_registries.items():
        collection = collections[collection_id]
        source = sources[collection_id]
        for context in registry.get("contexts", []):
            context_id = context.get("id")
            if (
                context.get("status") != "active"
                or not isinstance(context_id, str)
                or context_id not in concepts
                or _explicitly_negates_context(query, context)
            ):
                continue
            alternatives.append(
                {
                    "collection_id": collection_id,
                    "context_id": context_id,
                    "path": _prefix_collection_file(source, collection, context["path"]),
                    "score": 1.0,
                    "reasons": [f"shared_query_concept:{context_id}"],
                    "candidate_only": True,
                }
            )
    alternatives.sort(key=lambda item: (item["collection_id"], item["context_id"]))
    return alternatives


def _attach_exact_document(
    result: dict[str, Any],
    *,
    read_selector: Optional[str],
    root: Path,
    parent_revision: str,
    collections: dict[str, dict[str, Any]],
    sources: dict[str, CollectionSource],
) -> dict[str, Any]:
    if read_selector is None:
        return result
    first_file = result.get("first_file")
    if first_file is None:
        result["document"] = None
        return result
    allowed = {first_file, *result.get("deeper_suggestions", [])}
    requested = first_file if read_selector == "first" else _safe_relative(read_selector).as_posix()
    if requested not in allowed:
        raise ValueError("requested knowledge path was not authorized by this route")

    collection_id = result.get("collection_id")
    if collection_id is None:
        relative = _safe_relative(requested)
        content = _git_regular_blob(root, parent_revision, relative)
        source_commit = parent_revision
    else:
        collection = collections.get(collection_id)
        source = sources.get(collection_id)
        if collection is None or source is None:
            raise ValueError("routed collection source is unavailable")
        mount = _safe_relative(collection["mount"], one_part=True)
        logical = _safe_relative(requested)
        if not logical.parts or logical.parts[0] != mount.as_posix() or len(logical.parts) < 2:
            raise ValueError("requested knowledge path does not belong to the routed collection")
        content = _source_file_bytes(source, Path(*logical.parts[1:]))
        source_commit = source.revision
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("routed knowledge document must be UTF-8") from exc
    result["document"] = {
        "path": requested,
        "source_commit": source_commit,
        "sha256": hashlib.sha256(content).hexdigest(),
        "content": text,
    }
    return result


def route_knowledge(
    query: str,
    root: Path = ROOT,
    *,
    read_selector: Optional[str] = None,
) -> dict[str, Any]:
    """Route against committed snapshots and optionally return one authorized exact document."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")
    if read_selector is not None and (
        not isinstance(read_selector, str) or not read_selector.strip()
    ):
        raise ValueError("read selector must be 'first' or a routed logical path")
    if _is_private_profile_request(query):
        result = {
            "schema_version": 1,
            "decision": "abstain",
            "collection_id": None,
            "context_id": None,
            "first_file": None,
            "deeper_suggestions": [],
            "deeper_matches": [],
            "alternatives": [],
            "current_sources_required": False,
            "query_fingerprint": _query_fingerprint(query),
            "reason_codes": ["private_profile_explicit_only"],
            "trace": {"stage": "privacy_boundary", "engine_version": "2"},
        }
        if read_selector is not None:
            result["document"] = None
        return result

    parent_revision = _git_revision(root)
    registry_bytes = _git_regular_blob(root, parent_revision, REGISTRY_PATH)
    registry_digest = hashlib.sha256(registry_bytes).hexdigest()
    registry = load_collection_registry(
        root,
        content=registry_bytes,
        validate_worktree_paths=False,
    )
    if _git_revision(root) != parent_revision:
        raise ValueError("parent knowledge revision changed during routing")
    collections = {item["id"]: item for item in registry["collections"]}

    shared_concept_alternatives: list[dict[str, Any]] = []

    def finish(
        result: dict[str, Any],
        used_sources: dict[str, CollectionSource],
    ) -> dict[str, Any]:
        existing_alternatives = result.get("alternatives", [])
        if not isinstance(existing_alternatives, list):
            raise ValueError("route alternatives must be an array")
        seen = {
            (alternative.get("collection_id"), alternative.get("context_id"), alternative.get("path"))
            for alternative in existing_alternatives
            if isinstance(alternative, dict)
        }
        for alternative in shared_concept_alternatives:
            identity = (
                alternative.get("collection_id"),
                alternative.get("context_id"),
                alternative.get("path"),
            )
            if alternative.get("context_id") == result.get("context_id") or identity in seen:
                continue
            existing_alternatives.append(alternative)
            seen.add(identity)
        result["alternatives"] = existing_alternatives
        formal_confidence = result.pop("_formal_confidence", None)
        formal_context = result.get("context_id")
        reason_codes = result.get("reason_codes", [])
        conflicting_alternative = any(
            isinstance(alternative, dict)
            and alternative.get("context_id") not in (None, formal_context)
            for alternative in existing_alternatives
        )
        weak_term_only_route = (
            isinstance(reason_codes, list)
            and bool(reason_codes)
            and all(isinstance(reason, str) and reason.startswith("term:") for reason in reason_codes)
        )
        if (
            result.get("decision") == "load"
            and conflicting_alternative
            and weak_term_only_route
            and formal_confidence in {"low", "medium"}
        ):
            result.update(
                {
                    "decision": "ambiguous",
                    "context_id": None,
                    "first_file": None,
                    "deeper_suggestions": [],
                    "deeper_matches": [],
                    "reason_codes": [*reason_codes, "structured_alternative_conflict"],
                }
            )
        _attach_exact_document(
            result,
            read_selector=read_selector,
            root=root,
            parent_revision=parent_revision,
            collections=collections,
            sources=used_sources,
        )
        return _finalize_result(
            result,
            root=root,
            parent_revision=parent_revision,
            registry=registry,
            registry_digest=registry_digest,
            sources=used_sources,
        )

    if _contains_any(query, GLOBAL_ROOT_SIGNALS):
        result = _global_root_result(
            query,
            root,
            parent_revision=parent_revision,
            registry_digest=registry_digest,
        )
        return finish(result, {})
    if _contains_any(query, PERSONAL_ROOT_SIGNALS):
        collection = collections["personal_knowledge"]
        source = resolve_collection_source(root, collection)
        return finish(
            _collection_root_result(query, collection, source=source),
            {collection["id"]: source},
        )
    if _contains_any(query, WORK_ROOT_SIGNALS):
        collection = collections["work"]
        source = resolve_collection_source(root, collection)
        return finish(
            _collection_root_result(query, collection, source=source),
            {collection["id"]: source},
        )

    sources = resolve_collection_sources(root, registry)
    engine = _load_router_engine(root, registry, sources)
    engine_mount = PurePosixPath(registry["router_engine"]).parts[0]
    engine_collection = next(
        item for item in registry["collections"] if item["mount"] == engine_mount
    )
    engine_source = sources[engine_collection["id"]]
    context_registries = _load_context_registries(registry, sources, engine)
    shared_concept_alternatives = _shared_concept_alternatives(
        query,
        context_registries=context_registries,
        collections=collections,
        sources=sources,
    )
    explicit_binding = _explicit_context_binding(query, context_registries)
    if explicit_binding is not None:
        selected = {
            "decision": "load",
            "primary": explicit_binding[0],
            "alternatives": [],
            "current_sources_required": False,
            "query_fingerprint": _query_fingerprint(query),
        }
    else:
        selected = engine.route(
            query,
            _virtual_collection_registry(registry, context_registries),
            root=None,
        )
    if selected["decision"] != "load":
        ambiguous = "ambiguous_match" in selected.get("reasons", [])
        result = {
            "schema_version": 1,
            "decision": "ambiguous" if ambiguous else "abstain",
            "collection_id": None,
            "context_id": None,
            "first_file": None,
            "deeper_suggestions": [],
            "deeper_matches": [],
            "alternatives": _adapt_collection_alternatives(
                sources,
                collections,
                selected.get("alternatives", []),
            ),
            "current_sources_required": selected.get("current_sources_required", False),
            "query_fingerprint": selected["query_fingerprint"],
            "reason_codes": ["ambiguous_collection" if ambiguous else "no_collection_match"],
            "trace": {
                "stage": "collection_selection",
                "engine_version": "2",
                **engine_source.public_trace(),
            },
        }
        return finish(result, sources)

    collection_id = selected["primary"]
    collection = collections[collection_id]
    collection_source = sources[collection_id]
    with _materialize_source(collection_source) as snapshot_source:
        context_registry = engine.load_registry(snapshot_source.root)
        routed = engine.route(query, context_registry, root=snapshot_source.root)
    if explicit_binding is not None and (
        routed.get("decision") != "load" or routed.get("primary") != explicit_binding[1]
    ):
        bound_context = next(
            context
            for context in context_registries[collection_id]["contexts"]
            if context.get("status") == "active" and context.get("id") == explicit_binding[1]
        )
        routed = {
            "decision": "load",
            "primary": bound_context["id"],
            "first_file": bound_context["path"],
            "alternatives": [],
            "deeper_suggestions": [],
            "deeper_matches": [],
            "current_sources_required": False,
            "query_fingerprint": _query_fingerprint(query),
            "reasons": ["explicit_context_id"],
            "trace": {
                "router_version": "2",
                "retrieval_backend": "not_run",
                "degraded_reason": None,
                "evidence_candidates_read": 0,
            },
        }

    if routed.get("decision") == "load" and isinstance(routed.get("primary"), str):
        routed_context = next(
            (
                context
                for context in context_registries[collection_id].get("contexts", [])
                if context.get("status") == "active"
                and context.get("id") == routed.get("primary")
            ),
            None,
        )
        if routed_context is not None and _explicitly_negates_context(query, routed_context):
            result = {
                "schema_version": 1,
                "decision": "abstain",
                "collection_id": collection_id,
                "context_id": None,
                "first_file": None,
                "deeper_suggestions": [],
                "deeper_matches": [],
                "alternatives": _adapt_context_alternatives(
                    collection_source,
                    collection,
                    [
                        alternative
                        for alternative in routed.get("alternatives", [])
                        if alternative.get("context_id") != routed.get("primary")
                    ],
                ),
                "current_sources_required": bool(routed.get("current_sources_required", False))
                or _requires_current_source_safety_floor(query),
                "query_fingerprint": routed.get("query_fingerprint")
                or _query_fingerprint(query),
                "reason_codes": ["explicit_context_exclusion"],
                "trace": {
                    "stage": "context_selection",
                    "engine_version": str(routed.get("trace", {}).get("router_version", "2")),
                    "retrieval_backend": routed.get("trace", {}).get("retrieval_backend", "not_run"),
                    "degraded_reason": routed.get("trace", {}).get("degraded_reason"),
                    "evidence_candidates_read": routed.get("trace", {}).get("evidence_candidates_read", 0),
                    **collection_source.public_trace(),
                },
            }
            return finish(result, sources)

    if routed["decision"] == "abstain":
        plausible_other_collection = any(
            isinstance(item, dict) and float(item.get("score", 0.0)) > 0.0
            for item in selected.get("alternatives", [])
        )
        ambiguous = "ambiguous_match" in routed.get("reasons", []) or plausible_other_collection
        if plausible_other_collection:
            collection_alternatives = [
                {
                    "context_id": collection_id,
                    "score": selected.get("primary_score", 0.0),
                    "path": f"{collection_id}/README.md",
                    "reasons": selected.get("reasons", []),
                },
                *selected.get("alternatives", []),
            ]
            alternatives = _adapt_collection_alternatives(
                sources,
                collections,
                collection_alternatives,
            )
        else:
            alternatives = _adapt_context_alternatives(
                collection_source,
                collection,
                routed.get("alternatives", []),
            )
        result = {
            "schema_version": 1,
            "decision": "ambiguous" if ambiguous else "abstain",
            "collection_id": None if plausible_other_collection else collection_id,
            "context_id": None,
            "first_file": None,
            "deeper_suggestions": [],
            "deeper_matches": [],
            "alternatives": alternatives,
            "current_sources_required": routed.get("current_sources_required", False),
            "query_fingerprint": routed["query_fingerprint"],
            "reason_codes": [
                "ambiguous_collection"
                if plausible_other_collection
                else "ambiguous_context"
                if ambiguous
                else "no_context_match"
            ],
            "trace": {
                "stage": "context_selection",
                "engine_version": "2",
                **collection_source.public_trace(),
            },
        }
        return finish(result, sources)

    first_file = _prefix_collection_file(collection_source, collection, routed["first_file"])
    deeper_matches = []
    for match in routed.get("deeper_matches", []):
        adapted = dict(match)
        adapted["path"] = _prefix_collection_file(collection_source, collection, match["path"])
        deeper_matches.append(adapted)
    engine_requires_current = bool(routed.get("current_sources_required", False))
    safety_floor_requires_current = _requires_current_source_safety_floor(query)
    reason_codes = list(routed.get("reasons", []))
    if safety_floor_requires_current and not engine_requires_current:
        reason_codes.append("parent_current_source_safety_floor")
    result = {
        "schema_version": 1,
        "decision": routed["decision"],
        "collection_id": collection_id,
        "context_id": routed.get("primary"),
        "first_file": first_file,
        "deeper_suggestions": [
            _prefix_collection_file(collection_source, collection, value)
            for value in routed.get("deeper_suggestions", [])
        ],
        "deeper_matches": deeper_matches,
        "alternatives": _adapt_context_alternatives(
            collection_source,
            collection,
            routed.get("alternatives", []),
        ),
        "current_sources_required": engine_requires_current or safety_floor_requires_current,
        "query_fingerprint": routed["query_fingerprint"],
        "reason_codes": reason_codes,
        "_formal_confidence": routed.get("confidence"),
        "trace": {
            "stage": "context_selection",
            "engine_version": str(routed.get("trace", {}).get("router_version", "2")),
            "retrieval_backend": routed.get("trace", {}).get("retrieval_backend", "not_run"),
            "degraded_reason": routed.get("trace", {}).get("degraded_reason"),
            "evidence_candidates_read": routed.get("trace", {}).get("evidence_candidates_read", 0),
            **collection_source.public_trace(),
        },
    }
    return finish(result, sources)


def evaluate_knowledge_routes(root: Path = ROOT) -> dict[str, Any]:
    """Evaluate the parent collection decision and adapted context result end to end."""
    total = passed = 0
    failures: list[dict[str, Any]] = []
    with (root / EVAL_PATH).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            total += 1
            routed = route_knowledge(row["user_request"], root=root)
            expected = {
                "decision": row["expected_decision"],
                "collection_id": row["expected_collection"] or None,
                "context_id": row["expected_context"] or None,
                "first_file": row["expected_first_file"] or None,
            }
            actual = {key: routed.get(key) for key in expected}
            if actual == expected:
                passed += 1
            else:
                failures.append(
                    {
                        "case_id": row["id"],
                        "expected": expected,
                        "actual": actual,
                        "query_fingerprint": routed["query_fingerprint"],
                    }
                )
    return {"schema_version": 1, "total": total, "passed": passed, "failures": failures}
