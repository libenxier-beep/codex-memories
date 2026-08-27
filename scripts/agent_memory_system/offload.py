from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import re
from typing import Any, Mapping, Protocol, Sequence


class OffloadError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class OffloadStore(Protocol):
    """Atomic persistence seam owned by the runtime sidecar adapter.

    ``commit_offload_bundle`` must commit its evidence objects, task snapshot,
    checkpoint/version and receipt in one transaction, or commit none of them.
    """

    def commit_offload_bundle(self, bundle: dict[str, object]) -> dict[str, object]:
        ...

    def load_offload_task(
        self, task_id: str, version: int | None = None
    ) -> dict[str, object] | None:
        ...

    def load_offload_evidence(self, evidence_ref: str) -> dict[str, object] | None:
        ...

    def list_offload_evidence_refs(
        self, *, session_id: str, limit: int = 10_000
    ) -> list[str]:
        ...

    def list_offload_versions(self, task_id: str) -> list[int]:
        ...

    def restore_offload_evidence(self, evidence: Mapping[str, object]) -> bool:
        ...


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _source_cited(text: str, source_ref: str) -> str:
    normalized = " ".join(text.split())
    citation = "[source:{}]".format(source_ref)
    return normalized if citation in normalized else "{} {}".format(normalized, citation)


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_TASK_INVARIANT_FIELDS = {
    "schema_version",
    "goal",
    "hard_constraints",
    "decisions",
    "current_phase",
    "next_action",
    "open_blockers",
    "source_bindings",
}
_TASK_INVARIANT_BINDING_FIELDS = {
    "field",
    "item_index",
    "session_id",
    "event_id",
    "span_start",
    "span_end",
    "source_hash",
    "authority_type",
}
_TASK_CLAUSE = re.compile(r"[^，,。！？!?；;\n]+")
_TASK_CONSTRAINT = re.compile(
    r"(?:不要|不得|必须|只能|不能|别|务必|禁止|严禁|do\s+not|don't|must|only|never)",
    re.IGNORECASE,
)
_TASK_DECISION = re.compile(r"(?:就按|决定|采用|同意|确认使用|选择)")
_UNSAFE_TASK_SOURCE = re.compile(
    r"(?:```|https?://|\btraceback\b|\bsystem\s+prompt\b|"
    r"\bdeveloper\s+message\b|\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above)\s+instructions\b|"
    r"\[REDACTED\])",
    re.IGNORECASE,
)
_TOOL_OUTCOME_KEYS = {
    "schema_version",
    "tool_id",
    "status",
    "error_code",
    "metrics",
    "evidence_ref",
}
MAX_ACTIVE_TOOL_STEPS = 128
_TOOL_STATUSES = {"succeeded", "failed", "unknown"}
_TOOL_ERROR_CODES = {"none", "nonzero_exit", "tool_error", "unknown"}
_TRUSTED_TOOL_IDS = frozenset(
    {
        "apply_patch",
        "exec_command",
        "read_file",
        "read_log",
        "tool",
        "verify",
        "view_image",
        "web__run",
        "write_stdin",
    }
)


def _safe_identifier(value: object, *, fallback: str) -> str:
    text = str(value or "")
    return text if _SAFE_IDENTIFIER.fullmatch(text) else fallback


def _opaque_identity(namespace: str, value: object) -> str:
    return "sha256:" + hashlib.sha256(
        (namespace + "\x00" + str(value)).encode("utf-8")
    ).hexdigest()


def validate_task_invariant(value: object) -> dict[str, object]:
    """Validate the small, source-bound record allowed beside Offload v2."""

    if not isinstance(value, dict) or set(value) != _TASK_INVARIANT_FIELDS:
        raise OffloadError("unsafe_task_invariant", "task invariant schema is invalid")
    if value.get("schema_version") != 1:
        raise OffloadError("unsafe_task_invariant", "task invariant version is invalid")
    goal = value.get("goal")
    if not isinstance(goal, str) or not goal or len(goal) > 320:
        raise OffloadError("unsafe_task_invariant", "task invariant goal is invalid")
    text_fields: dict[str, list[str]] = {"goal": [goal]}
    for field in ("hard_constraints", "decisions", "open_blockers"):
        items = value.get(field)
        if (
            not isinstance(items, list)
            or len(items) > 4
            or any(not isinstance(item, str) or not item or len(item) > 320 for item in items)
            or len(items) != len(set(items))
        ):
            raise OffloadError("unsafe_task_invariant", "task invariant list is invalid")
        text_fields[field] = list(items)
    for field in ("current_phase", "next_action"):
        item = value.get(field)
        if item is not None and (not isinstance(item, str) or not item or len(item) > 320):
            raise OffloadError("unsafe_task_invariant", "task invariant advisory is invalid")
        text_fields[field] = [] if item is None else [item]
    if any(
        _UNSAFE_TASK_SOURCE.search(item)
        for items in text_fields.values()
        for item in items
    ):
        raise OffloadError("unsafe_task_invariant", "task invariant source is unsafe")

    bindings = value.get("source_bindings")
    expected_keys = {
        (field, index)
        for field, items in text_fields.items()
        for index, _item in enumerate(items)
    }
    if not isinstance(bindings, list) or len(bindings) != len(expected_keys):
        raise OffloadError("unsafe_task_invariant", "task invariant bindings are incomplete")
    seen: set[tuple[str, int]] = set()
    normalized_bindings: list[dict[str, object]] = []
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != _TASK_INVARIANT_BINDING_FIELDS:
            raise OffloadError("unsafe_task_invariant", "task invariant binding is invalid")
        field = binding.get("field")
        index = binding.get("item_index")
        if not isinstance(field, str) or not isinstance(index, int) or isinstance(index, bool):
            raise OffloadError("unsafe_task_invariant", "task invariant binding target is invalid")
        key = (field, index)
        if key not in expected_keys or key in seen:
            raise OffloadError("unsafe_task_invariant", "task invariant binding target is invalid")
        session_id = binding.get("session_id")
        event_id = binding.get("event_id")
        if any(
            not isinstance(item, str) or not item or "\x00" in item or len(item) > 512
            for item in (session_id, event_id)
        ):
            raise OffloadError("unsafe_task_invariant", "task invariant source identity is invalid")
        start = binding.get("span_start")
        end = binding.get("span_end")
        if (
            not isinstance(start, int)
            or isinstance(start, bool)
            or not isinstance(end, int)
            or isinstance(end, bool)
            or start < 0
            or end <= start
            or end - start != len(text_fields[field][index])
        ):
            raise OffloadError("unsafe_task_invariant", "task invariant source span is invalid")
        source_hash = binding.get("source_hash")
        if not isinstance(source_hash, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", source_hash):
            raise OffloadError("unsafe_task_invariant", "task invariant source hash is invalid")
        authority = binding.get("authority_type")
        if field == "current_phase":
            allowed_authorities = {"assistant_advisory"}
        elif field == "next_action":
            allowed_authorities = {"assistant_advisory", "user_authority"}
        else:
            allowed_authorities = {"user_authority"}
        if authority not in allowed_authorities:
            raise OffloadError("unsafe_task_invariant", "task invariant authority is invalid")
        seen.add(key)
        normalized_bindings.append(dict(binding))
    return {
        "schema_version": 1,
        "goal": goal,
        "hard_constraints": text_fields["hard_constraints"],
        "decisions": text_fields["decisions"],
        "current_phase": value["current_phase"],
        "next_action": value["next_action"],
        "open_blockers": text_fields["open_blockers"],
        "source_bindings": normalized_bindings,
    }


def render_task_invariant(value: object) -> str:
    validated = validate_task_invariant(value)
    return "[agent-memory-task-invariant v1]\n" + _canonical_json(validated).decode("utf-8")


def build_task_invariant(
    sources: Sequence[Mapping[str, object]], *, max_chars: int = 1100
) -> dict[str, object] | None:
    """Derive exact user spans only; tool, web and log prose never enter."""

    if max_chars < 512:
        raise OffloadError("invariant_budget_too_small", "task invariant budget is unsafe")
    clauses: list[tuple[str, int, int, Mapping[str, object]]] = []
    for source in sources:
        if source.get("evidence_type") != "user" or source.get("role") != "user":
            continue
        content = source.get("content")
        session_id = source.get("session_id")
        event_id = source.get("event_id")
        content_hash = source.get("content_hash")
        if (
            not isinstance(content, str)
            or not isinstance(session_id, str)
            or not isinstance(event_id, str)
            or not isinstance(content_hash, str)
            or hashlib.sha256(content.encode("utf-8")).hexdigest() != content_hash
        ):
            continue
        for match in _TASK_CLAUSE.finditer(content):
            start, end = match.span()
            while start < end and content[start].isspace():
                start += 1
            while end > start and content[end - 1].isspace():
                end -= 1
            if start == end:
                continue
            end = min(end, start + 320)
            text = content[start:end]
            if _UNSAFE_TASK_SOURCE.search(text):
                continue
            clauses.append((text, start, end, source))
    if not clauses:
        return None

    goal_clause = clauses[0]
    constraints = [clause for clause in clauses if _TASK_CONSTRAINT.search(clause[0])]
    decisions = [clause for clause in clauses if _TASK_DECISION.search(clause[0])]

    def unique(items: Sequence[tuple[str, int, int, Mapping[str, object]]]) -> list[tuple[str, int, int, Mapping[str, object]]]:
        result: list[tuple[str, int, int, Mapping[str, object]]] = []
        seen_text: set[str] = set()
        for item in items:
            if item[0] not in seen_text:
                seen_text.add(item[0])
                result.append(item)
        return result[:4]

    constraints = unique(constraints)
    decisions = unique(decisions)

    def assemble() -> dict[str, object]:
        selected = [("goal", 0, goal_clause)]
        selected.extend(("hard_constraints", index, item) for index, item in enumerate(constraints))
        selected.extend(("decisions", index, item) for index, item in enumerate(decisions))
        bindings = []
        for field, index, (text, start, end, source) in selected:
            bindings.append(
                {
                    "field": field,
                    "item_index": index,
                    "session_id": str(source["session_id"]),
                    "event_id": str(source["event_id"]),
                    "span_start": start,
                    "span_end": end,
                    "source_hash": "sha256:" + str(source["content_hash"]),
                    "authority_type": "user_authority",
                }
            )
        return {
            "schema_version": 1,
            "goal": goal_clause[0],
            "hard_constraints": [item[0] for item in constraints],
            "decisions": [item[0] for item in decisions],
            "current_phase": None,
            "next_action": None,
            "open_blockers": [],
            "source_bindings": bindings,
        }

    invariant = validate_task_invariant(assemble())
    while len(render_task_invariant(invariant)) > max_chars and (decisions or constraints):
        if decisions:
            decisions.pop()
        else:
            constraints.pop()
        invariant = validate_task_invariant(assemble())
    if len(render_task_invariant(invariant)) > max_chars:
        return None
    return invariant


def _closed_tool_id(value: object) -> str:
    tool_id = _safe_identifier(value, fallback="unknown_tool")
    return tool_id if tool_id in _TRUSTED_TOOL_IDS else "unknown_tool"


def _tool_outcome(
    tool_name: str,
    raw_result: str,
    evidence_ref: str,
    trusted_outcome: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Project untrusted tool bytes into a closed, non-prose status schema."""

    byte_count = len(raw_result.encode("utf-8"))
    line_count = raw_result.count("\n") + (1 if raw_result else 0)
    exit_code: int | None = None
    is_error: bool | None = None
    if isinstance(trusted_outcome, Mapping):
        supplied_exit = trusted_outcome.get("exit_code")
        if isinstance(supplied_exit, int) and not isinstance(supplied_exit, bool):
            if -255 <= supplied_exit <= 255:
                exit_code = supplied_exit
        supplied_error = trusted_outcome.get("is_error")
        if isinstance(supplied_error, bool):
            is_error = supplied_error
    if exit_code is not None:
        status = "succeeded" if exit_code == 0 else "failed"
        error_code = "none" if exit_code == 0 else "nonzero_exit"
    elif is_error is not None:
        status = "failed" if is_error else "succeeded"
        error_code = "tool_error" if is_error else "none"
    else:
        status = "unknown"
        error_code = "unknown"
    metrics: dict[str, int] = {
        "result_bytes": byte_count,
        "result_lines": line_count,
    }
    if exit_code is not None:
        metrics["exit_code"] = exit_code
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_ref):
        raise OffloadError("unsafe_offload_projection", "tool outcome evidence ref is invalid")
    return {
        "schema_version": 1,
        "tool_id": _closed_tool_id(tool_name),
        "status": status,
        "error_code": error_code,
        "metrics": metrics,
        "evidence_ref": evidence_ref,
    }


def _validated_tool_outcome(
    value: object, *, evidence_ref: str | None = None
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise OffloadError("unsafe_offload_projection", "tool outcome schema is invalid")
    normalized = copy.deepcopy(value)
    legacy_keys = _TOOL_OUTCOME_KEYS - {"evidence_ref"}
    if set(normalized) == legacy_keys and isinstance(evidence_ref, str):
        normalized["evidence_ref"] = evidence_ref
    if set(normalized) != _TOOL_OUTCOME_KEYS:
        raise OffloadError("unsafe_offload_projection", "tool outcome schema is invalid")
    if value.get("schema_version") != 1:
        raise OffloadError("unsafe_offload_projection", "tool outcome version is invalid")
    if value.get("tool_id") not in _TRUSTED_TOOL_IDS | {"unknown_tool"}:
        raise OffloadError("unsafe_offload_projection", "tool identifier is invalid")
    if value.get("status") not in _TOOL_STATUSES:
        raise OffloadError("unsafe_offload_projection", "tool status is invalid")
    if value.get("error_code") not in _TOOL_ERROR_CODES:
        raise OffloadError("unsafe_offload_projection", "tool error code is invalid")
    outcome_ref = normalized.get("evidence_ref")
    if (
        not isinstance(outcome_ref, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", outcome_ref)
        or (evidence_ref is not None and outcome_ref != evidence_ref)
    ):
        raise OffloadError("unsafe_offload_projection", "tool outcome evidence ref is invalid")
    metrics = normalized.get("metrics")
    if not isinstance(metrics, dict) or not {
        "result_bytes", "result_lines"
    }.issubset(metrics) or not set(metrics) <= {
        "result_bytes",
        "result_lines",
        "exit_code",
    }:
        raise OffloadError("unsafe_offload_projection", "tool metrics are invalid")
    for key, metric in metrics.items():
        if not isinstance(metric, int) or isinstance(metric, bool):
            raise OffloadError("unsafe_offload_projection", "tool metric type is invalid")
        if key in {"result_bytes", "result_lines"} and metric < 0:
            raise OffloadError("unsafe_offload_projection", "tool metric range is invalid")
        if key == "exit_code" and not -255 <= metric <= 255:
            raise OffloadError("unsafe_offload_projection", "tool exit code is invalid")
    status = normalized["status"]
    error_code = normalized["error_code"]
    exit_code = metrics.get("exit_code")
    if (
        (status == "succeeded" and error_code != "none")
        or (status == "failed" and error_code not in {"nonzero_exit", "tool_error"})
        or (status == "unknown" and error_code != "unknown")
        or (exit_code == 0 and status != "succeeded")
        or (isinstance(exit_code, int) and exit_code != 0 and status != "failed")
    ):
        raise OffloadError("unsafe_offload_projection", "tool outcome is inconsistent")
    return normalized


def validate_injection_projection(
    value: object,
    *,
    expected_task_id: str | None = None,
    expected_version: int | None = None,
) -> dict[str, object]:
    """Validate the only data shape allowed to cross into automatic context."""

    required = {
        "schema_version",
        "task_id",
        "version",
        "state",
        "current_step_id",
        "steps",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise OffloadError("unsafe_offload_projection", "offload projection schema is invalid")
    if value.get("schema_version") != 2:
        raise OffloadError("unsafe_offload_projection", "offload projection version is invalid")
    task_id = value.get("task_id")
    if not isinstance(task_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", task_id):
        raise OffloadError("unsafe_offload_projection", "offload task identifier is invalid")
    if expected_task_id is not None and task_id != _opaque_identity("task", expected_task_id):
        raise OffloadError("unsafe_offload_projection", "offload task identity is stale")
    version = value.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise OffloadError("unsafe_offload_projection", "offload task version is invalid")
    if expected_version is not None and version != expected_version:
        raise OffloadError("unsafe_offload_projection", "offload task version is stale")
    if value.get("state") not in {"active", "blocked", "complete", "cancelled"}:
        raise OffloadError("unsafe_offload_projection", "offload task state is invalid")
    current_step = value.get("current_step_id")
    if current_step is not None and (
        not isinstance(current_step, str)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", current_step)
    ):
        raise OffloadError("unsafe_offload_projection", "current step identifier is invalid")
    steps = value.get("steps")
    if not isinstance(steps, list):
        raise OffloadError("unsafe_offload_projection", "offload steps are invalid")
    validated_steps: list[dict[str, object]] = []
    seen_steps: set[str] = set()
    for step in steps:
        if not isinstance(step, dict) or set(step) != {
            "step_id",
            "state",
            "outcome",
            "evidence_ref",
            "depends_on",
        }:
            raise OffloadError("unsafe_offload_projection", "offload step schema is invalid")
        step_id = step.get("step_id")
        if (
            not isinstance(step_id, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", step_id)
            or step_id in seen_steps
        ):
            raise OffloadError("unsafe_offload_projection", "offload step identifier is invalid")
        if step.get("state") != "complete":
            raise OffloadError("unsafe_offload_projection", "offload step state is invalid")
        dependencies = step.get("depends_on")
        if not isinstance(dependencies, list) or any(
            not isinstance(dependency, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", dependency)
            for dependency in dependencies
        ):
            raise OffloadError("unsafe_offload_projection", "offload dependencies are invalid")
        if len(dependencies) != len(set(dependencies)) or step_id in dependencies:
            raise OffloadError("unsafe_offload_projection", "offload dependencies are invalid")
        evidence_ref = step.get("evidence_ref")
        if not isinstance(evidence_ref, str) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", evidence_ref
        ):
            raise OffloadError("unsafe_offload_projection", "offload evidence ref is invalid")
        seen_steps.add(str(step_id))
        validated_steps.append(
            {
                "step_id": step_id,
                "state": "complete",
                "outcome": _validated_tool_outcome(
                    step.get("outcome"), evidence_ref=evidence_ref
                ),
                "evidence_ref": evidence_ref,
                "depends_on": list(dependencies),
            }
        )
    return {
        "schema_version": 2,
        "task_id": task_id,
        "version": version,
        "state": value["state"],
        "current_step_id": current_step,
        "steps": validated_steps,
    }


def render_injection_projection(value: object) -> str:
    validated = validate_injection_projection(value)
    return "[agent-memory-offload v2]\n" + _canonical_json(validated).decode("utf-8")


def _evidence_object(
    *,
    task_id: str,
    task_version: int,
    step_id: str,
    tool_name: str,
    arguments: Mapping[str, object],
    result: str,
    source_ref: str,
) -> dict[str, object]:
    session_id = task_id[len("codex-session:") :] if task_id.startswith("codex-session:") else None
    pair: dict[str, object] = {
        "schema_version": 2,
        "task_id": task_id,
        "task_version": task_version,
        "session_id": session_id,
        "step_id": step_id,
        "call": {
            "tool_name": tool_name,
            "arguments": dict(arguments),
        },
        "result": result,
        "source_ref": source_ref,
    }
    raw = _canonical_json(pair)
    content_sha256 = hashlib.sha256(raw).hexdigest()
    return {
        "schema_version": 1,
        "evidence_ref": "sha256:{}".format(content_sha256),
        "content_sha256": content_sha256,
        "encoding": "gzip+base64+canonical-json",
        "payload": base64.b64encode(gzip.compress(raw, mtime=0)).decode("ascii"),
        "source_ref": source_ref,
    }


class OffloadEngine:
    """Versioned task graph with source-bound summaries and raw drill-down."""

    def __init__(self, store: OffloadStore) -> None:
        self.store = store

    def start_task(
        self,
        *,
        task_id: str,
        goal: str,
        constraints: Sequence[str],
        source_ref: str,
    ) -> dict[str, object]:
        if not task_id or not goal or not source_ref:
            raise OffloadError("invalid_task", "task id, goal and source reference are required")
        if self.store.load_offload_task(task_id) is not None:
            raise OffloadError("task_exists", "offload task already exists")
        snapshot: dict[str, object] = {
            "schema_version": 1,
            "task_id": task_id,
            "version": 1,
            "goal": goal,
            "goal_summary": _source_cited(goal, source_ref),
            "constraints": list(dict.fromkeys(constraints)),
            "source_ref": source_ref,
            "state": "active",
            "current_step_id": None,
            "steps": [],
            "task_graph": {},
            "archived_step_count": 0,
        }
        return self._commit(snapshot=snapshot, evidence=(), expected_version=0, operation="start")

    def record_tool_step(
        self,
        *,
        task_id: str,
        step_id: str,
        tool_name: str,
        arguments: Mapping[str, object],
        result: str,
        source_ref: str,
        summary: str,
        depends_on: Sequence[str] = (),
        expected_version: int,
        trusted_outcome: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        snapshot = self._load_exact(task_id, expected_version)
        if snapshot.get("state") not in {"active", "blocked"}:
            raise OffloadError("task_not_active", "cannot append evidence to a closed task")
        if any(step.get("step_id") == step_id for step in snapshot.get("steps", [])):
            raise OffloadError("duplicate_step", "step id already exists")
        known_steps = {
            str(step.get("step_id"))
            for step in snapshot.get("steps", [])
            if isinstance(step, dict)
        }
        dependencies = list(dict.fromkeys(depends_on))
        if step_id in dependencies:
            raise OffloadError("task_dependency_cycle", "a step cannot depend on itself")
        missing = [dependency for dependency in dependencies if dependency not in known_steps]
        if missing:
            raise OffloadError("task_dependency_missing", "task dependency is unavailable")
        evidence = _evidence_object(
            task_id=task_id,
            task_version=expected_version + 1,
            step_id=step_id,
            tool_name=tool_name,
            arguments=arguments,
            result=result,
            source_ref=source_ref,
        )
        outcome = _tool_outcome(
            tool_name,
            result,
            str(evidence["evidence_ref"]),
            trusted_outcome,
        )
        next_snapshot = copy.deepcopy(snapshot)
        next_snapshot["version"] = expected_version + 1
        next_snapshot["current_step_id"] = step_id
        next_snapshot.setdefault("steps", []).append(
            {
                "step_id": step_id,
                "state": "complete",
                "tool_name": tool_name,
                "summary": _source_cited(summary, source_ref),
                "outcome": outcome,
                "source_ref": source_ref,
                "evidence_ref": evidence["evidence_ref"],
                "content_sha256": evidence["content_sha256"],
                "evidence_task_version": expected_version + 1,
                "depends_on": dependencies,
            }
        )
        next_snapshot.setdefault("task_graph", {})[step_id] = dependencies
        active_steps = next_snapshot.setdefault("steps", [])
        if len(active_steps) > MAX_ACTIVE_TOOL_STEPS:
            retired = active_steps[: len(active_steps) - MAX_ACTIVE_TOOL_STEPS]
            del active_steps[: len(retired)]
            graph = next_snapshot.setdefault("task_graph", {})
            for retired_step in retired:
                graph.pop(str(retired_step.get("step_id") or ""), None)
            next_snapshot["archived_step_count"] = int(
                next_snapshot.get("archived_step_count") or 0
            ) + len(retired)
        return self._commit(
            snapshot=next_snapshot,
            evidence=(evidence,),
            expected_version=expected_version,
            operation="record_tool_step",
        )

    def drill_down(
        self, task_id: str, evidence_ref: str, *, expected_version: int
    ) -> dict[str, object]:
        snapshot = self._load_exact(task_id, expected_version)
        linked = [
            step
            for step in snapshot.get("steps", [])
            if isinstance(step, dict) and step.get("evidence_ref") == evidence_ref
        ]
        if len(linked) != 1:
            raise OffloadError("evidence_not_linked", "evidence is not linked by this task version")
        item = self.store.load_offload_evidence(evidence_ref)
        if item is None:
            raise OffloadError("evidence_missing", "raw evidence is unavailable")
        step = linked[0]
        return self._decode_evidence(
            item,
            evidence_ref,
            expected_task_id=task_id,
            expected_task_version=self._evidence_task_version(step),
            expected_step_id=str(step.get("step_id") or ""),
            expected_source_ref=str(step.get("source_ref") or ""),
        )

    def drill_down_archived(
        self, task_id: str, evidence_ref: str, *, expected_version: int
    ) -> dict[str, object]:
        """Explicitly reopen archived raw evidence by its opaque content ref."""

        self._load_exact(task_id, expected_version)
        item = self.store.load_offload_evidence(evidence_ref)
        if item is None:
            raise OffloadError("evidence_missing", "raw evidence is unavailable")
        try:
            compressed = base64.b64decode(str(item["payload"]), validate=True)
            raw = gzip.decompress(compressed)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or value.get("task_id") != task_id:
                raise ValueError("task binding mismatch")
            task_version = int(value["task_version"])
            step_id = str(value["step_id"])
            source_ref = str(value["source_ref"])
        except (KeyError, TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise OffloadError(
                "evidence_corrupt", "archived evidence failed integrity verification"
            ) from error
        return self._decode_evidence(
            item,
            evidence_ref,
            expected_task_id=task_id,
            expected_task_version=task_version,
            expected_step_id=step_id,
            expected_source_ref=source_ref,
        )

    def restore_evidence(
        self,
        task_id: str,
        evidence: Mapping[str, object],
        *,
        expected_version: int,
    ) -> dict[str, object]:
        """Restore a missing content-addressed raw object from trusted replay.

        The caller must reopen an immutable upstream evidence source.  This
        method proves that the supplied object decodes to its hash and is
        already linked by the exact task snapshot before the store may insert
        it.  No task version or summary is changed.
        """
        snapshot = self._load_exact(task_id, expected_version)
        evidence_ref = str(evidence.get("evidence_ref") or "")
        linked = {
            str(step.get("evidence_ref"))
            for step in snapshot.get("steps", [])
            if isinstance(step, dict)
        }
        if evidence_ref not in linked:
            raise OffloadError("evidence_not_linked", "restored evidence is not linked")
        linked_steps = [
            step
            for step in snapshot.get("steps", [])
            if isinstance(step, dict) and step.get("evidence_ref") == evidence_ref
        ]
        if len(linked_steps) != 1:
            raise OffloadError("evidence_not_linked", "restored evidence link is ambiguous")
        linked_step = linked_steps[0]
        decoded = self._decode_evidence(
            dict(evidence),
            evidence_ref,
            expected_task_id=task_id,
            expected_task_version=self._evidence_task_version(linked_step),
            expected_step_id=str(linked_step.get("step_id") or ""),
            expected_source_ref=str(linked_step.get("source_ref") or ""),
        )
        try:
            restored = self.store.restore_offload_evidence(evidence)
        except Exception as error:
            raise OffloadError(
                "evidence_restore_failed", "raw evidence restore failed: {}".format(error)
            ) from error
        if not restored and self.store.load_offload_evidence(evidence_ref) is None:
            raise OffloadError("evidence_restore_failed", "raw evidence was not restored")
        verified = self.drill_down(task_id, evidence_ref, expected_version=expected_version)
        if verified != decoded:
            raise OffloadError("evidence_restore_failed", "restored evidence changed")
        return verified

    def update_task(
        self,
        *,
        task_id: str,
        state: str,
        current_step_id: str | None,
        status_summary: str,
        source_ref: str,
        expected_version: int,
    ) -> dict[str, object]:
        if state not in {"active", "blocked", "complete", "cancelled"}:
            raise OffloadError("invalid_task_state", "task state is invalid")
        snapshot = self._load_exact(task_id, expected_version)
        next_snapshot = copy.deepcopy(snapshot)
        next_snapshot["version"] = expected_version + 1
        next_snapshot["state"] = state
        next_snapshot["current_step_id"] = current_step_id
        next_snapshot["status_summary"] = _source_cited(status_summary, source_ref)
        next_snapshot["status_source_ref"] = source_ref
        return self._commit(
            snapshot=next_snapshot,
            evidence=(),
            expected_version=expected_version,
            operation="update_task",
        )

    def build_injection_projection(
        self, task_id: str, *, expected_version: int, max_chars: int
    ) -> dict[str, object]:
        if max_chars < 256:
            raise OffloadError("injection_budget_too_small", "offload injection budget is unsafe")
        snapshot = self._load_exact(task_id, expected_version)
        task_state = snapshot.get("state")
        if task_state not in {"active", "blocked", "complete", "cancelled"}:
            raise OffloadError("unsafe_offload_projection", "task state is invalid")
        current_step = snapshot.get("current_step_id")
        if current_step is not None:
            current_step = _opaque_identity("step", current_step)
        projection: dict[str, object] = {
            "schema_version": 2,
            "task_id": _opaque_identity("task", task_id),
            "version": expected_version,
            "state": task_state,
            "current_step_id": current_step,
            "steps": [],
        }
        if len(render_injection_projection(projection)) > max_chars:
            raise OffloadError("injection_budget_exceeded", "protected task context exceeds budget")
        for step in reversed(snapshot.get("steps", [])):
            if not isinstance(step, dict):
                raise OffloadError("unsafe_offload_projection", "offload step is invalid")
            raw_step_id = step.get("step_id")
            if not isinstance(raw_step_id, str) or not raw_step_id:
                raise OffloadError("unsafe_offload_projection", "offload step identifier is invalid")
            step_id = _opaque_identity("step", raw_step_id)
            evidence_ref = str(step.get("evidence_ref") or "")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", evidence_ref):
                raise OffloadError("unsafe_offload_projection", "offload step reference is invalid")
            item = {
                "step_id": step_id,
                "state": "complete",
                "outcome": _validated_tool_outcome(
                    step.get("outcome"), evidence_ref=evidence_ref
                ),
                "evidence_ref": evidence_ref,
                "depends_on": [
                    _opaque_identity("step", dependency)
                    for dependency in step.get("depends_on", [])
                    if isinstance(dependency, str) and dependency
                ],
            }
            candidate = copy.deepcopy(projection)
            candidate["steps"] = list(reversed([item, *list(reversed(projection["steps"]))]))
            rendered = render_injection_projection(candidate)
            if len(rendered) > max_chars:
                break
            projection = candidate
        return validate_injection_projection(
            projection,
            expected_task_id=task_id,
            expected_version=expected_version,
        )

    def build_injection(self, task_id: str, *, expected_version: int, max_chars: int) -> str:
        return render_injection_projection(
            self.build_injection_projection(
                task_id,
                expected_version=expected_version,
                max_chars=max_chars,
            )
        )

    def replay(self, task_id: str, *, expected_version: int) -> dict[str, object]:
        snapshot = self._load_exact(task_id, expected_version)
        evidence = []
        for step in snapshot.get("steps", []):
            evidence.append(
                self.drill_down(
                    task_id,
                    str(step["evidence_ref"]),
                    expected_version=expected_version,
                )
            )
        return {
            "schema_version": 1,
            "task_id": task_id,
            "version": expected_version,
            "snapshot": snapshot,
            "evidence": evidence,
            "integrity": "verified",
        }

    def compact_context(
        self,
        task_id: str,
        messages: Sequence[Mapping[str, object]],
        *,
        expected_version: int,
        target_chars: int,
        recent_messages: int = 2,
    ) -> dict[str, object]:
        if target_chars < 1 or recent_messages < 0:
            raise OffloadError("invalid_compaction_budget", "compaction budget is invalid")
        snapshot = self._load_exact(task_id, expected_version)
        copied = [dict(item) for item in messages]
        before_chars = len(_canonical_json(copied))
        injection = self.build_injection(
            task_id,
            expected_version=expected_version,
            max_chars=max(256, min(2000, max(target_chars, 256))),
        )
        if before_chars <= target_chars:
            return {
                "schema_version": 1,
                "task_id": task_id,
                "version": expected_version,
                "level": "none",
                "messages": copied,
                "injection": injection,
                "token_reduction_ratio": 0.0,
                "degraded_reason": None,
            }

        ratio = target_chars / max(before_chars, 1)
        if ratio >= 0.60:
            level = "mild"
        elif ratio >= 0.35:
            level = "aggressive"
        else:
            level = "emergency"

        units = self._message_units(copied)
        protected_start = max(0, len(copied) - recent_messages)
        step_by_ref = {
            str(step["evidence_ref"]): step for step in snapshot.get("steps", [])
        }
        unreferenced_pair = False
        rendered: list[dict[str, object]] = []
        current_chars = before_chars
        for unit in units:
            items = unit["items"]
            if unit["kind"] != "tool_pair":
                rendered.extend(items)
                continue
            protected = unit["end"] > protected_start or any(
                bool(item.get("constraint")) for item in items
            )
            refs = {str(item.get("evidence_ref", "")) for item in items}
            ref = refs.pop() if len(refs) == 1 else ""
            step = step_by_ref.get(ref)
            if not ref or step is None:
                unreferenced_pair = True
                rendered.extend(items)
                continue
            # Integrity must be established before any original tool bytes are removed.
            self.drill_down(task_id, ref, expected_version=expected_version)
            compact_projection = {
                "schema_version": 1,
                "outcome": _validated_tool_outcome(
                    step.get("outcome"), evidence_ref=ref
                ),
                "evidence_ref": ref,
            }
            summary_item = {
                "kind": "offload_summary",
                "schema_version": 2,
                # Keep the chat-facing field inert and compact.  The closed outcome
                # and its evidence reference are already carried as typed siblings;
                # serializing them again here needlessly consumes context budget.
                "content": "typed tool outcome retained; raw result requires explicit drill",
                "outcome": compact_projection["outcome"],
                "evidence_ref": ref,
            }
            saved = len(_canonical_json(items)) - len(_canonical_json(summary_item))
            should_replace = not protected and (
                level == "emergency"
                or (level == "aggressive" and current_chars > target_chars)
                or (level == "mild" and current_chars > target_chars)
            )
            if should_replace:
                rendered.append(summary_item)
                current_chars -= max(0, saved)
            else:
                rendered.extend(items)

        after_chars = len(_canonical_json(rendered))
        degraded_reason = None
        if after_chars > target_chars and unreferenced_pair:
            degraded_reason = "unreferenced_tool_evidence"
        elif after_chars > target_chars:
            degraded_reason = "protected_context_exceeds_budget"
        return {
            "schema_version": 1,
            "task_id": task_id,
            "version": expected_version,
            "level": level,
            "messages": rendered,
            "injection": injection,
            "token_reduction_ratio": max(0.0, (before_chars - after_chars) / max(before_chars, 1)),
            "degraded_reason": degraded_reason,
        }

    @staticmethod
    def _message_units(messages: Sequence[dict[str, object]]) -> list[dict[str, object]]:
        units: list[dict[str, object]] = []
        index = 0
        while index < len(messages):
            item = messages[index]
            kind = item.get("kind")
            if kind == "tool_call":
                if index + 1 >= len(messages):
                    raise OffloadError("tool_pair_incomplete", "tool call has no adjacent result")
                result = messages[index + 1]
                if (
                    result.get("kind") != "tool_result"
                    or not item.get("tool_call_id")
                    or result.get("tool_call_id") != item.get("tool_call_id")
                ):
                    raise OffloadError("tool_pair_incomplete", "tool call/result adjacency is invalid")
                units.append(
                    {
                        "kind": "tool_pair",
                        "start": index,
                        "end": index + 2,
                        "items": [item, result],
                    }
                )
                index += 2
                continue
            if kind == "tool_result":
                raise OffloadError("tool_pair_incomplete", "tool result has no adjacent call")
            units.append({"kind": "message", "start": index, "end": index + 1, "items": [item]})
            index += 1
        return units

    def _load_exact(self, task_id: str, expected_version: int) -> dict[str, object]:
        snapshot = self.store.load_offload_task(task_id, expected_version)
        if snapshot is None:
            current = self.store.load_offload_task(task_id)
            if current is None:
                raise OffloadError("task_missing", "offload task does not exist")
            raise OffloadError("stale_task_version", "requested task version is unavailable")
        if int(snapshot.get("version", -1)) != expected_version:
            raise OffloadError("stale_task_version", "store returned a different task version")
        return snapshot

    def _commit(
        self,
        *,
        snapshot: dict[str, object],
        evidence: Sequence[dict[str, object]],
        expected_version: int,
        operation: str,
    ) -> dict[str, object]:
        snapshot_digest = _digest(snapshot)
        receipt: dict[str, object] = {
            "schema_version": 1,
            "operation": operation,
            "task_id": snapshot["task_id"],
            "version": snapshot["version"],
            "expected_version": expected_version,
            "snapshot_digest": snapshot_digest,
            "evidence_refs": [item["evidence_ref"] for item in evidence],
            "status": "committed",
        }
        receipt["receipt_id"] = "offload:{}".format(_digest(receipt))
        bundle: dict[str, object] = {
            "schema_version": 1,
            "expected_version": expected_version,
            "snapshot": snapshot,
            "snapshot_digest": snapshot_digest,
            "evidence": list(evidence),
            "receipt": receipt,
        }
        try:
            returned = self.store.commit_offload_bundle(bundle)
        except OffloadError:
            raise
        except Exception as error:
            raise OffloadError("offload_commit_failed", "atomic offload commit failed") from error
        return returned

    @staticmethod
    def _evidence_task_version(step: Mapping[str, object]) -> int:
        version = step.get("evidence_task_version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise OffloadError(
                "evidence_scope_mismatch",
                "offload step does not bind its evidence creation version",
            )
        return version

    @staticmethod
    def _decode_evidence(
        item: Mapping[str, object],
        expected_ref: str,
        *,
        expected_task_id: str,
        expected_task_version: int,
        expected_step_id: str,
        expected_source_ref: str,
    ) -> dict[str, object]:
        try:
            if item.get("encoding") != "gzip+base64+canonical-json":
                raise ValueError("unsupported encoding")
            compressed = base64.b64decode(str(item["payload"]), validate=True)
            raw = gzip.decompress(compressed)
            digest = hashlib.sha256(raw).hexdigest()
            if expected_ref != "sha256:{}".format(digest):
                raise ValueError("reference mismatch")
            if item.get("content_sha256") != digest:
                raise ValueError("digest mismatch")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("evidence is not an object")
        except (KeyError, ValueError, OSError, UnicodeError, json.JSONDecodeError) as error:
            raise OffloadError("evidence_corrupt", "raw evidence failed integrity verification") from error
        expected_session_id = (
            expected_task_id[len("codex-session:") :]
            if expected_task_id.startswith("codex-session:")
            else None
        )
        if (
            value.get("schema_version") != 2
            or value.get("task_id") != expected_task_id
            or value.get("task_version") != expected_task_version
            or value.get("session_id") != expected_session_id
            or value.get("step_id") != expected_step_id
            or value.get("source_ref") != expected_source_ref
            or item.get("source_ref") != expected_source_ref
        ):
            raise OffloadError(
                "evidence_scope_mismatch",
                "raw evidence does not bind the requested session, task, version, step and source",
            )
        return value
