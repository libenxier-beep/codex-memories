"""Current-host adapter for bounded progressive memory retrieval.

The active Codex model supplies typed planner decisions between local tool
calls.  Every call replays the bounded deterministic host loop from the
original query, so no authority handle or candidate body must be trusted from
caller-owned state.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Any, Mapping, Optional, Sequence

import progressive_knowledge_access as progressive


FROZEN_CANDIDATE_COMMIT = "cb0761fcc072dac32ac20a493aa85bb46deab9e8"
FROZEN_CANDIDATE_TREE = "6c38ceedebce016ddd57829327b8898d20324530"


def _candidate_binding() -> dict[str, str]:
    return {
        "commit": FROZEN_CANDIDATE_COMMIT,
        "tree": FROZEN_CANDIDATE_TREE,
    }


class ProgressiveHostError(ValueError):
    """Stable error raised at the current-host progressive seam."""


ACTIVATION_SCHEMA = "cm-progressive-host-activation-v1"


def _state_directory(path: Path, *, create: bool) -> Path:
    if not path.is_absolute():
        raise ProgressiveHostError("state_directory_must_be_absolute")
    if create:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise ProgressiveHostError("state_directory_unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise ProgressiveHostError("state_directory_unsafe")
    return path


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.parent / ".{}.next-{}-{}".format(
        path.name, os.getpid(), secrets.token_hex(4)
    )
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def set_mode(state_dir: Path, mode: str) -> dict[str, object]:
    if mode not in {"candidate", "legacy"}:
        raise ProgressiveHostError("mode_invalid")
    directory = _state_directory(state_dir, create=True)
    value: dict[str, object] = {
        "schema_version": ACTIVATION_SCHEMA,
        "mode": mode,
        "candidate_binding": _candidate_binding(),
    }
    _atomic_json(directory / "activation.json", value)
    return value


def activation_status(state_dir: Path) -> dict[str, object]:
    if not state_dir.exists():
        return {
            "schema_version": ACTIVATION_SCHEMA,
            "mode": "legacy",
            "candidate_binding": _candidate_binding(),
        }
    directory = _state_directory(state_dir, create=False)
    path = directory / "activation.json"
    if not path.exists():
        return {
            "schema_version": ACTIVATION_SCHEMA,
            "mode": "legacy",
            "candidate_binding": _candidate_binding(),
        }
    try:
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ProgressiveHostError("activation_file_unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProgressiveHostError("activation_file_invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != ACTIVATION_SCHEMA
        or value.get("mode") not in {"candidate", "legacy"}
        or value.get("candidate_binding") != _candidate_binding()
    ):
        raise ProgressiveHostError("activation_file_invalid")
    return dict(value)


class ProgressiveSessionController:
    """Owner-only durable handoff between the prompt hook and current Codex."""

    def __init__(
        self,
        state_dir: Path,
        *,
        advance_fn: object = None,
        root: Optional[Path] = None,
        codex_home: Optional[Path] = None,
        graph_root: Optional[Path] = None,
    ) -> None:
        self.state_dir = state_dir
        self.advance_fn = advance if advance_fn is None else advance_fn
        if not callable(self.advance_fn):
            raise ProgressiveHostError("advance_callback_invalid")
        self.root = root
        self.codex_home = codex_home
        self.graph_root = graph_root

    def is_enabled(self) -> bool:
        return activation_status(self.state_dir)["mode"] == "candidate"

    def _sessions(self) -> Path:
        directory = _state_directory(self.state_dir, create=True) / "sessions"
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        return _state_directory(directory, create=False)

    def _session_path(self, token: str) -> Path:
        if not isinstance(token, str) or len(token) != 32:
            raise ProgressiveHostError("session_token_invalid")
        try:
            int(token, 16)
        except ValueError as error:
            raise ProgressiveHostError("session_token_invalid") from error
        return self._sessions() / (token + ".json")

    def _cleanup_stale_sessions(self, *, now: float) -> None:
        cutoff = now - 86_400
        for path in self._sessions().glob("*.json"):
            try:
                metadata = os.lstat(path)
                if (
                    stat.S_ISREG(metadata.st_mode)
                    and not stat.S_ISLNK(metadata.st_mode)
                    and metadata.st_uid == os.getuid()
                    and not metadata.st_mode & 0o077
                    and metadata.st_mtime < cutoff
                ):
                    path.unlink()
            except FileNotFoundError:
                continue

    def _read_session(self, token: str) -> dict[str, object]:
        path = self._session_path(token)
        try:
            metadata = os.lstat(path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
                or metadata.st_size > 1024 * 1024
            ):
                raise ProgressiveHostError("session_file_unsafe")
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as error:
            raise ProgressiveHostError("session_not_found") from error
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ProgressiveHostError("session_file_invalid") from error
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != "cm-progressive-host-session-v1"
            or value.get("session_token") != token
            or value.get("candidate_binding") != _candidate_binding()
            or value.get("state") not in {"active", "complete"}
            or not isinstance(value.get("decisions"), list)
            or not isinstance(value.get("allowed_scopes"), list)
            or not value.get("allowed_scopes")
            or any(
                scope not in {"work", "personal"}
                for scope in value.get("allowed_scopes", [])
            )
        ):
            raise ProgressiveHostError("session_file_invalid")
        return dict(value)

    def _run(self, value: Mapping[str, object]) -> dict[str, object]:
        query = value.get("query")
        if not isinstance(query, str) or not query.strip():
            raise ProgressiveHostError("session_query_unavailable")
        decisions = value.get("decisions")
        if not isinstance(decisions, list):
            raise ProgressiveHostError("session_decisions_invalid")
        options: dict[str, object] = {}
        if self.root is not None:
            options["root"] = self.root
        if self.codex_home is not None:
            options["codex_home"] = self.codex_home
        if self.graph_root is not None:
            options["graph_root"] = self.graph_root
        result = self.advance_fn(
            query,
            decisions=decisions,
            query_id=str(value["query_id"]),
            allowed_scopes=tuple(value["allowed_scopes"]),
            **options,
        )
        if not isinstance(result, Mapping) or result.get("status") not in {
            "awaiting_decision",
            "complete",
        }:
            raise ProgressiveHostError("advance_result_invalid")
        return {"session_token": value["session_token"], **dict(result)}

    def start(
        self,
        *,
        query: str,
        codex_session_id: str,
        allowed_scopes: tuple[str, ...],
    ) -> dict[str, object]:
        if activation_status(self.state_dir)["mode"] != "candidate":
            raise ProgressiveHostError("candidate_not_enabled")
        if not isinstance(codex_session_id, str) or not codex_session_id.strip():
            raise ProgressiveHostError("codex_session_id_invalid")
        if (
            not isinstance(allowed_scopes, tuple)
            or not allowed_scopes
            or any(scope not in {"work", "personal"} for scope in allowed_scopes)
            or len(set(allowed_scopes)) != len(allowed_scopes)
        ):
            raise ProgressiveHostError("allowed_scopes_invalid")
        self._cleanup_stale_sessions(now=time.time())
        token = secrets.token_hex(16)
        value: dict[str, object] = {
            "schema_version": "cm-progressive-host-session-v1",
            "session_token": token,
            "query_id": "live:" + token,
            "codex_session_id": codex_session_id,
            "allowed_scopes": list(allowed_scopes),
            "query": query,
            "decisions": [],
            "state": "active",
            "candidate_binding": _candidate_binding(),
        }
        result = self._run(value)
        _atomic_json(self._session_path(token), value)
        return result

    def show(self, token: str) -> dict[str, object]:
        value = self._read_session(token)
        if value["state"] != "active":
            raise ProgressiveHostError("session_closed")
        return self._run(value)

    def step(
        self, token: str, decision: Mapping[str, Any]
    ) -> dict[str, object]:
        value = self._read_session(token)
        if value["state"] != "active":
            raise ProgressiveHostError("session_closed")
        decisions = list(value["decisions"])
        decisions.append(dict(decision))
        proposed = {**value, "decisions": decisions}
        result = self._run(proposed)
        if result["status"] == "complete":
            proposed = {
                key: item
                for key, item in proposed.items()
                if key not in {"query", "decisions"}
            }
            proposed["decisions"] = []
            proposed["state"] = "complete"
        _atomic_json(self._session_path(token), proposed)
        return result


@dataclass
class _NeedDecision(Exception):
    observation: progressive.PlannerObservation


class _ReplayPlanner:
    def __init__(self, decisions: Sequence[progressive.PlannerDecision]) -> None:
        self._decisions = tuple(decisions)
        self._index = 0

    def plan(
        self, observation: progressive.PlannerObservation
    ) -> progressive.PlannerDecision:
        if self._index >= len(self._decisions):
            raise _NeedDecision(observation)
        decision = self._decisions[self._index]
        self._index += 1
        return decision


def _observation_view(
    observation: progressive.PlannerObservation,
) -> dict[str, object]:
    return {
        "schema_version": "cm-progressive-host-observation-v1",
        "query_id": observation.request.query_id,
        "round": observation.round_index,
        "visible_evidence": [
            {
                "candidate_id": item.candidate_id,
                "evidence_group_id": item.evidence_group_id,
                "summary": item.summary,
                "body": item.body,
                "retrieval_score": float(item.retrieval_score),
                "authorization_handles": list(item.authorization_handles),
                "authority": (
                    item.authority.as_dict() if item.authority is not None else None
                ),
            }
            for item in observation.visible_evidence
        ],
        "available_authorization_handles": list(
            observation.available_authorization_handles
        ),
        "recent_action_outcomes": [
            dict(value) for value in observation.recent_action_outcomes
        ],
        "budget": {
            "remaining_calls": observation.remaining_calls,
            "remaining_body_chars": observation.remaining_body_chars,
            "remaining_candidate_evaluations": (
                observation.remaining_candidate_evaluations
            ),
        },
        "decision_contract": {
            "fields": sorted(progressive.DECISION_FIELDS),
            "action_fields": sorted(progressive.ACTION_FIELDS),
            "actions": sorted(progressive.ACTION_KINDS),
            "query_view_kinds": sorted(progressive.QUERY_VIEW_KINDS),
            "evidence_statuses": sorted(progressive.EVIDENCE_STATUSES),
            "stop_reasons": sorted(progressive.STOP_REASONS),
        },
    }


def advance(
    query: str,
    *,
    decisions: Sequence[Mapping[str, Any]],
    host: Optional[progressive.RetrievalHost] = None,
    query_id: str,
    allowed_scopes: Sequence[str] = (),
    root: Optional[Path] = None,
    codex_home: Optional[Path] = None,
    graph_root: Optional[Path] = None,
) -> dict[str, object]:
    """Replay prior decisions and yield the next observation or final result."""

    if not isinstance(query, str) or not query.strip():
        raise ProgressiveHostError("query_invalid")
    if not isinstance(query_id, str) or not query_id.strip():
        raise ProgressiveHostError("query_id_invalid")
    if not isinstance(decisions, Sequence) or isinstance(decisions, (str, bytes)):
        raise ProgressiveHostError("decisions_invalid")
    if len(decisions) > progressive.LoopBudgets().max_rounds:
        raise ProgressiveHostError("decision_budget_exceeded")
    try:
        parsed = tuple(progressive.parse_planner_decision(value) for value in decisions)
    except (TypeError, ValueError, progressive.PlannerProtocolError) as error:
        raise ProgressiveHostError("decision_invalid") from error
    planner = _ReplayPlanner(parsed)
    if host is None:
        options: dict[str, object] = {}
        if root is not None:
            options["root"] = root
        if codex_home is not None:
            options["codex_home"] = codex_home
        if graph_root is not None:
            options["graph_root"] = graph_root
        host = progressive.GovernedKnowledgeHost(**options)
    if (
        not isinstance(allowed_scopes, Sequence)
        or isinstance(allowed_scopes, (str, bytes))
        or any(scope not in {"work", "personal"} for scope in allowed_scopes)
    ):
        raise ProgressiveHostError("allowed_scopes_invalid")
    request = progressive.RetrievalRequest(
        query_id=query_id, text=query, allowed_scopes=tuple(allowed_scopes)
    )
    try:
        result = progressive.run_progressive_retrieval(
            request,
            planner=planner,
            host=host,
            bootstrap_action=progressive.RetrievalAction(
                kind="search",
                query_view_kind="original",
                query=query,
            ),
        )
    except _NeedDecision as pending:
        return {
            "schema_version": "cm-progressive-host-advance-v1",
            "status": "awaiting_decision",
            "decisions_consumed": len(parsed),
            "candidate_binding": _candidate_binding(),
            "observation": _observation_view(pending.observation),
        }
    return {
        "schema_version": "cm-progressive-host-advance-v1",
        "status": "complete",
        "decisions_consumed": len(parsed),
        "candidate_binding": _candidate_binding(),
        "result": result,
    }
