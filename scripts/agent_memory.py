#!/usr/bin/env python3
"""Operate the governed, local-only Codex Agent Memory pipeline."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any, Mapping, Sequence

from agent_memory_system.candidates import CandidateFormer, CandidateJobDispatcher
from agent_memory_system.capture import TranscriptCapture
from agent_memory_system.embedding import LocalNaturalLanguageEmbedding
from agent_memory_system.hooks import CodexHookAdapter, MAX_HOOK_INPUT_BYTES
from agent_memory_system.governance import CandidateGovernanceBridge
from agent_memory_system.lifecycle import LifecycleResolver
from agent_memory_system.offload import OffloadEngine, build_task_invariant
from agent_memory_system.paths import (
    AUTHORITY_INDEX_PATH,
    EMBEDDING_CACHE_PATH,
    EMBEDDING_HELPER_PATH,
    HYBRID_INDEX_PATH,
    RUNTIME_ROOT,
    STATE_PATH,
)
from agent_memory_system.reliability import PipelineReliability
from agent_memory_system.retrieval import (
    GovernedHybridRetrieval,
    INDEX_SCHEMA_VERSION,
    embedding_manifest_mismatches,
)
from agent_memory_system.store import AgentMemoryStore, stable_id
from agent_memory_system.routing import route_memory_query
from memory_control_plane.projection import MemoryProjection
from memory_control_plane.recall_policy import (
    RecallPolicy,
    RecallPolicyError,
    parse_recall_policy,
    verify_recall_request,
)
from memory_control import control_plane


def route_knowledge(
    query: str,
    *,
    root: Path,
    read_selector: str | None = None,
    profile: str = "auto",
) -> dict[str, Any]:
    """Compatibility seam for callers that patched the original router."""

    del read_selector
    return route_memory_query(query, root=root, profile=profile)


def _trusted_git_executable() -> str:
    for candidate in ("/usr/bin/git", "/bin/git"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    resolved = shutil.which("git", path=os.defpath)
    if resolved is None or not os.path.isabs(resolved):
        raise ValueError("a trusted absolute Git executable is required")
    return os.path.realpath(resolved)


def _governed_git_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
    }


ROOT = Path(__file__).resolve().parents[1]
CODEX_HOME = ROOT.parent
DEFAULT_RUNTIME_ROOT = RUNTIME_ROOT
DEFAULT_STATE = STATE_PATH
DEFAULT_AUTHORITY_INDEX = AUTHORITY_INDEX_PATH
DEFAULT_HYBRID_INDEX = HYBRID_INDEX_PATH
DEFAULT_EMBEDDING_CACHE = EMBEDDING_CACHE_PATH
EMBEDDING_HELPER = EMBEDDING_HELPER_PATH
STAGES = ("capture", "distill", "index", "recall", "offload")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    return value


def _embedding(cache_dir: Path) -> LocalNaturalLanguageEmbedding:
    return LocalNaturalLanguageEmbedding(helper_source=EMBEDDING_HELPER, cache_dir=cache_dir)


def _retrieval(
    *, root: Path, authority_index: Path, hybrid_index: Path, embedding_cache: Path
) -> GovernedHybridRetrieval:
    authority = MemoryProjection(
        repository=root.resolve(strict=True),
        index_path=authority_index,
        authority_roots=("core", "platform", "learnings"),
    )
    return GovernedHybridRetrieval(
        authority=authority,
        index_path=hybrid_index,
        embedding=_embedding(embedding_cache),
    )


class ProductionHookRuntime:
    """Codex-native callbacks; indexes propose IDs and Git remains authority."""

    def __init__(
        self,
        *,
        store: AgentMemoryStore,
        root: Path,
        router_root: Path | None = None,
        router_profile: str = "auto",
        authority_index: Path,
        hybrid_index: Path,
        embedding_cache: Path,
        trusted_transcript_roots: tuple[Path, ...] = (),
        memory_enabled: bool = True,
        recall_policy: RecallPolicy | Mapping[str, Any] | None = None,
        progressive_controller: object | None = None,
        progressive_command_prefix: str | None = None,
    ) -> None:
        self.store = store
        self.root = root
        self.router_root = root if router_root is None else router_root
        self.router_profile = router_profile
        self.authority_index = authority_index
        self.hybrid_index = hybrid_index
        self.embedding_cache = embedding_cache
        self.memory_enabled = memory_enabled
        self.recall_policy = (
            parse_recall_policy(recall_policy) if recall_policy is not None else None
        )
        self.progressive_controller = progressive_controller
        self.progressive_command_prefix = progressive_command_prefix
        self.capture = TranscriptCapture(store, trusted_roots=trusted_transcript_roots)
        self.former = CandidateFormer(store)
        self.dispatcher = CandidateJobDispatcher(store)
        self.reliability = PipelineReliability(store)
        self.offload = OffloadEngine(store)
        # Retrieval is deliberately lazy.  A missing RecallPolicy is an
        # abstention, not permission to open indexes or initialize embeddings.
        self.retrieval = None

    def _runtime_retrieval(self) -> GovernedHybridRetrieval:
        retrieval = getattr(self, "retrieval", None)
        if retrieval is None:
            retrieval = _retrieval(
                root=self.root,
                authority_index=self.authority_index,
                hybrid_index=self.hybrid_index,
                embedding_cache=self.embedding_cache,
            )
            self.retrieval = retrieval
        return retrieval

    def capture_incremental(
        self, *, session_id: str, transcript_path: str, cwd: str, flush: bool
    ) -> Mapping[str, Any]:
        receipt = self.capture.capture_jsonl(session_id, transcript_path)
        candidates = self.dispatcher.dispatch_pending(
            worker_id="hook-capture:{}".format(session_id),
            limit=4,
        )
        try:
            offload = self._sync_offload(session_id)
        except Exception as error:
            self.record_pipeline_error(
                "offload",
                "automatic_offload_failed",
                "{}: {}".format(type(error).__name__, error),
                "session:" + session_id,
            )
            offload = {"status": "degraded", "reason": type(error).__name__}
        return {"capture": asdict(receipt), "candidates": candidates, "offload": offload, "flush": flush}

    def capture_prompt(
        self,
        *,
        session_id: str,
        prompt: str,
        cwd: str,
        source_event_id: str | None,
    ) -> Mapping[str, Any]:
        receipt = self.store.capture_hook_prompt(
            session_id=session_id,
            prompt=prompt,
            cwd=cwd,
            source_event_id=source_event_id,
        )
        candidates = self.dispatcher.dispatch_pending(
            worker_id="hook-prompt:{}".format(session_id),
            limit=4,
        )
        return {"capture": receipt, "candidates": candidates}

    def capture_tool_call(
        self,
        *,
        session_id: str,
        cwd: str,
        turn_id: str | None,
        tool_use_id: str,
        tool_name: str,
        tool_input: object,
    ) -> Mapping[str, Any]:
        content = json.dumps(
            {"name": tool_name, "arguments": tool_input},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return self.store.capture_hook_observation(
            session_id=session_id,
            event_name="PreToolUse",
            evidence_type="tool_call",
            role=None,
            content=content,
            cwd=cwd,
            source_event_id=tool_use_id,
            metadata={"call_id": tool_use_id, "turn_id": turn_id, "tool_name": tool_name},
        )

    def capture_tool_result(
        self,
        *,
        session_id: str,
        cwd: str,
        turn_id: str | None,
        tool_use_id: str,
        tool_name: str,
        tool_response: object,
        trusted_outcome: Mapping[str, object] | None = None,
    ) -> Mapping[str, Any]:
        content = (
            tool_response
            if isinstance(tool_response, str)
            else json.dumps(
                tool_response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        receipt = self.store.capture_hook_observation(
            session_id=session_id,
            event_name="PostToolUse",
            evidence_type="tool_result",
            role=None,
            content=content,
            cwd=cwd,
            source_event_id=tool_use_id,
            metadata={
                "call_id": tool_use_id,
                "turn_id": turn_id,
                "tool_name": tool_name,
                # Hook tool_response is attacker-controlled evidence. Only a
                # separately supplied host-authenticated envelope can assert
                # execution status; the production hook protocol supplies no
                # such envelope today, so its status remains unknown.
                "host_outcome": _host_tool_outcome(trusted_outcome),
            },
        )
        try:
            offload = self._sync_offload(session_id)
        except Exception as error:
            self.record_pipeline_error(
                "offload",
                "automatic_offload_failed",
                "{}: {}".format(type(error).__name__, error),
                "session:" + session_id,
            )
            offload = {"status": "degraded", "reason": type(error).__name__}
        return {"capture": receipt, "offload": offload}

    def capture_assistant(
        self,
        *,
        session_id: str,
        cwd: str,
        turn_id: str | None,
        content: str,
    ) -> Mapping[str, Any]:
        source_event_id = turn_id or stable_id("assistant-turn", session_id, content)
        receipt = self.store.capture_hook_observation(
            session_id=session_id,
            event_name="Stop",
            evidence_type="assistant",
            role="assistant",
            content=content,
            cwd=cwd,
            source_event_id=source_event_id,
            metadata={"turn_id": turn_id},
            queue_distill=True,
        )
        candidates = self.dispatcher.dispatch_pending(
            worker_id="hook-stop:{}".format(session_id),
            limit=4,
        )
        return {"capture": receipt, "candidates": candidates}

    def recall_governed(
        self, *, query: str, cwd: str, session_id: str
    ) -> Sequence[Mapping[str, object]]:
        if not getattr(self, "memory_enabled", True):
            self.reliability.heartbeat(
                "recall", cursor="memory_disabled", now=_now(), status="disabled"
            )
            return []
        configured_policy = getattr(self, "recall_policy", None)
        if configured_policy is None:
            self.record_pipeline_error(
                "recall",
                "recall_policy_missing",
                "explicit RecallPolicy v1 is required",
                "session:" + session_id,
            )
            self.reliability.heartbeat(
                "recall", cursor="policy_missing", now=_now(), status="abstained"
            )
            return []
        try:
            privacy_route = route_knowledge(
                query,
                root=getattr(self, "router_root", self.root),
                profile=getattr(self, "router_profile", "auto"),
            )
            request = verify_recall_request(
                query,
                configured_policy,
                route_result=privacy_route,
                entry_point="native_hook",
                session_id=session_id,
            )
        except Exception as error:
            self.record_pipeline_error(
                "recall",
                "recall_query_classification_failed",
                type(error).__name__,
                "session:" + session_id,
            )
            self.reliability.heartbeat(
                "recall", cursor="classification_failed", now=_now(), status="abstained"
            )
            return []
        controller = getattr(self, "progressive_controller", None)
        if controller is not None:
            try:
                enabled = controller.is_enabled()
            except Exception as error:
                self.record_pipeline_error(
                    "recall",
                    "progressive_activation_invalid",
                    type(error).__name__,
                    "session:" + session_id,
                )
                self.reliability.heartbeat(
                    "recall", cursor="progressive_activation_invalid", now=_now(), status="abstained"
                )
                return []
            if enabled:
                route_collection = privacy_route.get("collection_id")
                allowed_collection = (
                    "personal"
                    if request.classification == "private_profile"
                    else route_collection
                    if route_collection in {"work", "personal"}
                    else "work"
                )
                return self._recall_progressive(
                    controller=controller,
                    query=query,
                    session_id=session_id,
                    allowed_scopes=(allowed_collection,),
                )
        try:
            result = self._runtime_retrieval().recall(
                query,
                context=request.policy,
                limit=5,
                governance_trace_stage="host_injection",
                request_binding=request.to_mapping(),
            )
        except Exception as error:
            self.record_pipeline_error(
                "recall", "governed_recall_degraded", type(error).__name__, "session:" + session_id
            )
            result = {"status": "degraded", "source_revision": None, "matches": []}
        self.reliability.heartbeat(
            "recall", cursor=str(result.get("source_revision") or "none"), now=_now(), status=str(result.get("status"))
        )
        rendered: list[dict[str, object]] = []
        for match in result.get("matches", []):
            if not isinstance(match, Mapping) or match.get("canonical_reopened") is not True:
                continue
            rendered.append(
                {
                    "authority_reopened": True,
                    "governance": "pass",
                    "content": str(match.get("evidence", "")),
                    "source_ref": str(match.get("source_ref", "")),
                    "authority_revision": str(match.get("source_revision", "")),
                }
            )
        return rendered

    def _recall_progressive(
        self,
        *,
        controller: object,
        query: str,
        session_id: str,
        allowed_scopes: tuple[str, ...],
    ) -> Sequence[Mapping[str, object]]:
        expected_binding = {
            "commit": "cb0761fcc072dac32ac20a493aa85bb46deab9e8",
            "tree": "6c38ceedebce016ddd57829327b8898d20324530",
        }
        try:
            bundle = controller.start(
                query=query,
                codex_session_id=session_id,
                allowed_scopes=allowed_scopes,
            )
            if not isinstance(bundle, Mapping):
                raise ValueError("progressive_bundle_invalid")
            if bundle.get("status") != "awaiting_decision":
                raise ValueError("progressive_bootstrap_status_invalid")
            if bundle.get("candidate_binding") != expected_binding:
                raise ValueError("progressive_candidate_binding_invalid")
            token = bundle.get("session_token")
            observation = bundle.get("observation")
            command_prefix = getattr(self, "progressive_command_prefix", None)
            if (
                not isinstance(token, str)
                or len(token) != 32
                or any(character not in "0123456789abcdef" for character in token)
                or not isinstance(observation, Mapping)
                or not isinstance(command_prefix, str)
            ):
                raise ValueError("progressive_control_invalid")
            visible = observation.get("visible_evidence")
            if not isinstance(visible, list):
                raise ValueError("progressive_evidence_invalid")
            rendered: list[dict[str, object]] = []
            for item in visible:
                if not isinstance(item, Mapping):
                    continue
                authority = item.get("authority")
                body = item.get("body")
                if (
                    not isinstance(authority, Mapping)
                    or authority.get("verified") is not True
                    or not isinstance(body, str)
                    or not body.strip()
                ):
                    continue
                path = authority.get("path")
                locator = authority.get("locator")
                revision = authority.get("source_revision")
                if not all(
                    isinstance(value, str) and value.strip()
                    for value in (path, locator, revision)
                ):
                    continue
                rendered.append(
                    {
                        "authority_reopened": True,
                        "governance": "pass",
                        "content": body,
                        "source_ref": "{}#{}".format(path, locator),
                        "authority_revision": revision,
                    }
                )
            rendered.append(
                {
                    "retrieval_control": True,
                    "protocol_version": "cm-progressive-codex-host-v1",
                    "session_token": token,
                    "command_prefix": command_prefix,
                    "candidate_binding": expected_binding,
                }
            )
        except Exception as error:
            self.record_pipeline_error(
                "recall",
                "progressive_bootstrap_failed",
                type(error).__name__,
                "session:" + session_id,
            )
            self.reliability.heartbeat(
                "recall", cursor="progressive_bootstrap_failed", now=_now(), status="abstained"
            )
            return []
        self.reliability.heartbeat(
            "recall", cursor=str(bundle.get("candidate_binding", {}).get("commit")), now=_now(), status="ready"
        )
        return rendered

    def offload_context(
        self, *, session_id: str, cwd: str
    ) -> Sequence[Mapping[str, object]]:
        if not getattr(self, "memory_enabled", True):
            return []
        task_id = "codex-session:{}".format(session_id)
        snapshot = self.store.load_offload_task(task_id)
        if snapshot is None or snapshot.get("state") not in {"active", "blocked"}:
            return []
        version = int(snapshot["version"])
        # Every summary line references immutable raw evidence.  Re-open and
        # verify each ref before presenting the current task view; corrupt raw
        # bytes fail closed instead of leaving an apparently healthy summary.
        for step in snapshot.get("steps", []):
            if not isinstance(step, Mapping) or not isinstance(step.get("evidence_ref"), str):
                return []
            self.offload.drill_down(task_id, str(step["evidence_ref"]), expected_version=version)
        projection = self.offload.build_injection_projection(
            task_id, expected_version=version, max_chars=1500
        )
        invariant = build_task_invariant(
            self.store.list_task_invariant_sources(session_id), max_chars=1200
        )
        return [
            {
                "task_reopened": True,
                "evidence_verified": True,
                "task_invariant_verified": invariant is not None,
                "task_id": task_id,
                "version": version,
                "projection": projection,
                "task_invariant": invariant,
            }
        ]

    def _sync_offload(self, session_id: str) -> Mapping[str, object]:
        scan_totals = {
            "sql_rows_read": 0,
            "metadata_decodes": 0,
            "evidence_decodes": 0,
            "scan_queries": 0,
            "dead_lettered": 0,
        }
        while True:
            scan = self.store.ingest_offload_sync_delta(session_id)
            scan_totals["sql_rows_read"] += int(scan["rows_read"])
            scan_totals["metadata_decodes"] += int(scan["metadata_decodes"])
            scan_totals["scan_queries"] += int(scan["scan_queries"])
            scan_totals["dead_lettered"] += int(scan["dead_lettered"])
            if not scan["has_more"]:
                break
        task_id = "codex-session:{}".format(session_id)
        snapshot = self.store.load_offload_task(task_id)
        if snapshot is not None and snapshot.get("state") not in {"active", "blocked"}:
            return {
                "status": "closed",
                "task_id": task_id,
                "version": snapshot.get("version"),
                **scan_totals,
            }

        added = 0
        processed = 0
        while True:
            pair = self.store.next_offload_sync_pair(session_id)
            if pair is None:
                break
            scan_totals["evidence_decodes"] += int(pair["evidence_decodes"])
            call = pair["call"]
            result = pair["result"]
            if snapshot is None:
                self.offload.start_task(
                    task_id=task_id,
                    goal="Codex session tool-evidence task",
                    constraints=(),
                    source_ref="evidence:{}+{}".format(
                        call["event_id"], result["event_id"]
                    ),
                )
                snapshot = self.store.load_offload_task(task_id)
            if snapshot is None:
                raise RuntimeError("offload task start did not persist")
            if snapshot.get("state") not in {"active", "blocked"}:
                return {
                    "status": "closed",
                    "task_id": task_id,
                    "version": snapshot.get("version"),
                    **scan_totals,
                }
            known = {
                str(step.get("step_id"))
                for step in snapshot.get("steps", [])
                if isinstance(step, Mapping)
            }
            step_id = "tool:{}".format(result["event_id"])
            if step_id in known:
                self.store.complete_offload_sync_pair(
                    str(pair["pair_id"]),
                    step_id=step_id,
                    receipt={
                        "schema_version": 1,
                        "pair_id": str(pair["pair_id"]),
                        "task_id": task_id,
                        "step_id": step_id,
                        "task_version": int(snapshot["version"]),
                        "status": "applied",
                    },
                )
                processed += 1
                continue
            try:
                call_payload = json.loads(str(call.get("content") or "{}"))
            except json.JSONDecodeError:
                call_payload = {}
            if not isinstance(call_payload, dict):
                call_payload = {}
            arguments = call_payload.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw_arguments": arguments}
            if not isinstance(arguments, dict):
                arguments = {"value": arguments}
            tool_name = str(call_payload.get("name") or call_payload.get("action") or "tool")
            raw_result = str(result.get("content") or "")
            version = int(snapshot["version"])
            result_metadata = result.get("metadata")
            trusted_outcome = (
                result_metadata.get("host_outcome")
                if isinstance(result_metadata, Mapping)
                else None
            )
            try:
                self.offload.record_tool_step(
                    task_id=task_id,
                    step_id=step_id,
                    tool_name=tool_name,
                    arguments=arguments,
                    result=raw_result,
                    source_ref="evidence:{}+{}".format(call["event_id"], result["event_id"]),
                    # Automatic context may expose only the Offload engine's
                    # closed outcome schema. Raw result prose remains drill-down
                    # evidence and never becomes a summary instruction surface.
                    summary="",
                    expected_version=version,
                    trusted_outcome=(
                        trusted_outcome if isinstance(trusted_outcome, Mapping) else None
                    ),
                )
                snapshot = self.store.load_offload_task(task_id)
                if snapshot is None:
                    raise RuntimeError("offload step did not persist")
                self.store.complete_offload_sync_pair(
                    str(pair["pair_id"]),
                    step_id=step_id,
                    receipt={
                        "schema_version": 1,
                        "pair_id": str(pair["pair_id"]),
                        "task_id": task_id,
                        "step_id": step_id,
                        "task_version": int(snapshot["version"]),
                        "status": "applied",
                    },
                )
            except Exception as error:
                failure = self.store.fail_offload_sync_pair(
                    str(pair["pair_id"]),
                    "pair_apply_{}".format(type(error).__name__.lower()),
                    retryable=True,
                )
                if failure["status"] == "pending":
                    return {
                        "status": "degraded",
                        "reason": "offload_pair_retry_pending",
                        "task_id": task_id,
                        "version": snapshot.get("version") if snapshot else None,
                        **scan_totals,
                    }
                scan_totals["dead_lettered"] += 1
                snapshot = self.store.load_offload_task(task_id)
                continue
            added += 1
            processed += 1
        if snapshot is None:
            return {
                "status": "not_needed",
                "pairs": processed,
                "added": added,
                **scan_totals,
            }
        return {
            "status": "updated" if added else "current",
            "task_id": task_id,
            "version": snapshot["version"],
            "pairs": processed,
            "added": added,
            **scan_totals,
        }

    def recover(self, *, session_id: str) -> Mapping[str, Any]:
        recovery = asdict(self.reliability.recover(now=_now()))
        recovery["retention_gc"] = self.store.run_retention_gc(
            now=_now().isoformat().replace("+00:00", "Z"),
            request_id=None,
        )
        recovery["candidate_backfill"] = self.dispatcher.enqueue_missing(
            session_id=session_id,
            now=_now(),
        )
        recovery["distill_dispatch"] = self.dispatcher.dispatch_pending(
            worker_id="hook-start:{}".format(session_id),
            limit=4,
        )
        if getattr(self, "recall_policy", None) is None:
            recovery["index_recovery"] = {
                "action": "abstained",
                "reason": "recall_policy_missing",
            }
        else:
            recovery["index_recovery"] = _recover_indexes(
                store=self.store,
                retrieval=self._runtime_retrieval(),
                root=self.root,
                authority_index=self.authority_index,
                hybrid_index=self.hybrid_index,
                embedding_cache=self.embedding_cache,
                recall_policy=self.recall_policy,
            )
        return recovery

    def record_pipeline_error(
        self, stage: str, error_code: str, detail: str, source_ref: str | None = None
    ) -> None:
        self.reliability.record_error(stage, error_code, detail, source_ref)


def _host_tool_outcome(host_envelope: object) -> Mapping[str, object] | None:
    """Extract status only from the distinct trusted-host envelope seam."""

    if not isinstance(host_envelope, Mapping):
        return None
    outcome: dict[str, object] = {}
    exit_code = host_envelope.get("exit_code")
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and -255 <= exit_code <= 255:
        outcome["exit_code"] = exit_code
    is_error = host_envelope.get("is_error")
    if isinstance(is_error, bool):
        outcome["is_error"] = is_error
    return outcome or None


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--state", type=Path, default=DEFAULT_STATE)
    root.add_argument("--root", type=Path, default=ROOT)
    root.add_argument(
        "--router-root",
        type=Path,
        help="trusted committed router authority (defaults to --root)",
    )
    root.add_argument(
        "--router-profile",
        choices=("auto", "collections", "local-authority"),
        default="auto",
        help="query-classification adapter (auto uses collections when configured)",
    )
    root.add_argument("--authority-index", type=Path, default=DEFAULT_AUTHORITY_INDEX)
    root.add_argument("--hybrid-index", type=Path, default=DEFAULT_HYBRID_INDEX)
    root.add_argument("--embedding-cache", type=Path, default=DEFAULT_EMBEDDING_CACHE)
    root.add_argument(
        "--progressive-state-dir",
        type=Path,
        help="owner-only local activation and host-loop state",
    )
    root.add_argument("--progressive-codex-home", type=Path, help=argparse.SUPPRESS)
    root.add_argument("--progressive-graph-root", type=Path, help=argparse.SUPPRESS)
    root.add_argument(
        "--receipt-path",
        type=Path,
        help="atomically write a digest-only receipt for a hook response",
    )
    root.add_argument(
        "--transcript-root",
        type=Path,
        action="append",
        default=[],
        help="trusted root containing host-owned session transcripts (repeatable)",
    )
    root.add_argument(
        "--memory-mode",
        choices=("enabled", "disabled"),
        default="enabled",
        help="keep native hooks active while disabling recall/offload injection for paired evaluation",
    )
    recall_policy_source = root.add_mutually_exclusive_group()
    recall_policy_source.add_argument(
        "--recall-policy-file",
        "--recall-context-file",
        dest="recall_policy_file",
        type=Path,
        help="bounded local JSON RecallPolicy v1 (legacy alias: --recall-context-file)",
    )
    recall_policy_source.add_argument(
        "--recall-policy-profile",
        choices=("local-work",),
        help="versioned built-in policy resolved at process start",
    )
    commands = root.add_subparsers(dest="command", required=True)

    capture = commands.add_parser("capture", help="incrementally capture a real Codex transcript")
    capture.add_argument("--session-id", required=True)
    capture.add_argument("--transcript", type=Path, required=True)

    distill = commands.add_parser("distill", help="form governed memory candidates from captured evidence")
    distill.add_argument("--session-id", required=True)

    lifecycle = commands.add_parser("lifecycle", help="resolve candidate lifecycle actions without applying them")
    lifecycle.add_argument("--session-id")
    lifecycle.add_argument("--now")

    proposal = commands.add_parser("proposal", help="prepare a candidate in the existing control plane")
    proposal_commands = proposal.add_subparsers(dest="proposal_command", required=True)
    prepare = proposal_commands.add_parser("prepare")
    prepare.add_argument("--candidate-id", required=True)
    prepare.add_argument("--destination", required=True)
    prepare.add_argument("--scope", choices=("global", "platform", "learning"), required=True)
    prepare.add_argument("--applies-to", choices=("all", "codex"), default="codex")
    prepare.add_argument("--gates-file", type=Path, required=True)
    tombstone = proposal_commands.add_parser("tombstone")
    tombstone.add_argument("--candidate-id", required=True)
    tombstone.add_argument("--gates-file", type=Path, required=True)

    index = commands.add_parser("index", help="rebuild committed lexical and local semantic projections")
    index.add_argument("--revision", default="HEAD")
    index.add_argument(
        "--query",
        help="bind router classification before query-specific pre-index filtering",
    )

    recall = commands.add_parser("recall", help="recall IDs, reopen authority, and apply governance")
    recall.add_argument("query", nargs="+")
    recall.add_argument("--limit", type=int, default=5)

    progressive = commands.add_parser(
        "progressive",
        help="let the current Codex host drive bounded progressive recall",
    )
    progressive_commands = progressive.add_subparsers(
        dest="progressive_command", required=True
    )
    progressive_commands.add_parser("enable", help="enable the candidate for live hooks")
    progressive_commands.add_parser("status", help="show the local activation state")
    progressive_commands.add_parser("rollback", help="return live hooks to legacy recall")
    progressive_show = progressive_commands.add_parser(
        "show", help="show the next governed observation for the current Codex"
    )
    progressive_show.add_argument("--session-token", required=True)
    progressive_step = progressive_commands.add_parser(
        "step", help="submit one typed current-Codex planner decision"
    )
    progressive_step.add_argument("--session-token", required=True)
    progressive_step.add_argument("--decision-json", required=True)

    offload = commands.add_parser("offload", help="maintain and drill into a long-task evidence graph")
    offload_commands = offload.add_subparsers(dest="offload_command", required=True)
    start = offload_commands.add_parser("start")
    start.add_argument("--task-id", required=True)
    start.add_argument("--goal", required=True)
    start.add_argument("--constraint", action="append", default=[])
    start.add_argument("--source-ref", required=True)
    step = offload_commands.add_parser("step")
    step.add_argument("--task-id", required=True)
    step.add_argument("--step-id", required=True)
    step.add_argument("--tool", required=True)
    step.add_argument("--arguments-json", default="{}")
    step.add_argument("--result", required=True)
    step.add_argument("--summary", required=True)
    step.add_argument("--source-ref", required=True)
    step.add_argument("--depends-on", action="append", default=[])
    step.add_argument("--version", type=int, required=True)
    update = offload_commands.add_parser("update")
    update.add_argument("--task-id", required=True)
    update.add_argument("--state-value", choices=("active", "blocked", "complete", "cancelled"), required=True)
    update.add_argument("--current-step-id")
    update.add_argument("--summary", required=True)
    update.add_argument("--source-ref", required=True)
    update.add_argument("--version", type=int, required=True)
    compact = offload_commands.add_parser("compact")
    compact.add_argument("--task-id", required=True)
    compact.add_argument("--messages-file", type=Path, required=True)
    compact.add_argument("--target-chars", type=int, required=True)
    compact.add_argument("--recent-messages", type=int, default=2)
    compact.add_argument("--version", type=int, required=True)
    inject = offload_commands.add_parser("inject")
    inject.add_argument("--task-id", required=True)
    inject.add_argument("--version", type=int, required=True)
    inject.add_argument("--max-chars", type=int, default=4000)
    drill = offload_commands.add_parser("drill")
    drill.add_argument("--task-id", required=True)
    drill.add_argument("--evidence-ref", required=True)
    drill.add_argument("--version", type=int, required=True)
    replay = offload_commands.add_parser("replay")
    replay.add_argument("--task-id", required=True)
    replay.add_argument("--version", type=int, required=True)

    commands.add_parser("recover", help="requeue expired work or send exhausted work to the DLQ")
    health = commands.add_parser("health", help="explain stage lag, failures, queues, and degradation")
    health.add_argument("--stale-after-seconds", type=int, default=3600)
    commands.add_parser("hook", help="serve one Codex hook event from JSON stdin")
    return root


def _runtime(args: argparse.Namespace, store: AgentMemoryStore) -> ProductionHookRuntime:
    recall_policy = _configured_recall_policy(args)
    progressive_controller = None
    progressive_command_prefix = None
    if args.progressive_state_dir is not None:
        from progressive_host import ProgressiveSessionController

        progressive_controller = ProgressiveSessionController(
            args.progressive_state_dir,
            root=args.root,
            codex_home=args.progressive_codex_home,
            graph_root=args.progressive_graph_root,
        )
        command = [
            "/usr/bin/python3",
            str(Path(__file__).resolve()),
            "--root",
            str(args.root),
            "--progressive-state-dir",
            str(args.progressive_state_dir),
        ]
        if args.progressive_codex_home is not None:
            command.extend(["--progressive-codex-home", str(args.progressive_codex_home)])
        if args.progressive_graph_root is not None:
            command.extend(["--progressive-graph-root", str(args.progressive_graph_root)])
        command.append("progressive")
        progressive_command_prefix = " ".join(shlex.quote(value) for value in command)
    return ProductionHookRuntime(
        store=store,
        root=args.root,
        router_root=args.router_root,
        router_profile=args.router_profile,
        authority_index=args.authority_index,
        hybrid_index=args.hybrid_index,
        embedding_cache=args.embedding_cache,
        trusted_transcript_roots=tuple(args.transcript_root),
        memory_enabled=args.memory_mode == "enabled",
        recall_policy=recall_policy,
        progressive_controller=progressive_controller,
        progressive_command_prefix=progressive_command_prefix,
    )


def _health(store: AgentMemoryStore, args: argparse.Namespace) -> Mapping[str, Any]:
    report = PipelineReliability(store).health(
        now=_now(), stale_after_seconds=args.stale_after_seconds
    )
    observed = {str(row["stage"]): dict(row) for row in report.stages}
    stages = {
        stage: observed.get(
            stage,
            {"stage": stage, "status": "never_run", "cursor": None, "updated_at": None},
        )
        for stage in STAGES
    }
    index = _index_health(args)
    candidate_formation = CandidateFormer(store).coverage_report()
    status = report.status
    if (
        index.get("stale")
        or index.get("status") != "ready"
        or index.get("semantic_status") != "ready"
        or candidate_formation["missing_durable_signals"] > 0
    ):
        status = "failed" if status == "failed" else "degraded"
    return {
        "schema_version": 1,
        "status": status,
        "stages": stages,
        "stale_stages": report.stale_stages,
        "expired_leases": report.expired_leases,
        "dead_jobs": report.dead_jobs,
        "pending_jobs": report.pending_jobs,
        "recent_errors": report.recent_errors,
        "retention": report.retention,
        "offload_sync": report.offload_sync,
        "candidate_formation": candidate_formation,
        "index": index,
    }


def _index_health(args: argparse.Namespace) -> Mapping[str, Any]:
    return _index_health_for_paths(
        root=args.root,
        authority_index=args.authority_index,
        hybrid_index=args.hybrid_index,
        embedding_cache=args.embedding_cache,
    )


def _index_health_for_paths(
    *,
    root: Path,
    authority_index: Path,
    hybrid_index: Path,
    embedding_cache: Path,
    recall_policy: RecallPolicy | None = None,
) -> Mapping[str, Any]:
    authority_present = authority_index.is_file() and not authority_index.is_symlink()
    hybrid_present = hybrid_index.is_file() and not hybrid_index.is_symlink()
    result: dict[str, Any] = {
        "authority_path": str(authority_index.resolve(strict=False)),
        "hybrid_path": str(hybrid_index.resolve(strict=False)),
        "authority_present": authority_present,
        "hybrid_present": hybrid_present,
        "status": "never_built" if not hybrid_present else "unknown",
        "stale": False,
        "source_revision": None,
        "current_revision": None,
        "semantic_status": "unavailable",
        "semantic_reason": "index_unavailable" if not hybrid_present else "metadata_unreadable",
        "semantic_description": {},
        "current_semantic_description": {},
        "index_schema_version": None,
        "expected_index_schema_version": str(INDEX_SCHEMA_VERSION),
    }
    if not hybrid_present:
        return result
    try:
        connection = sqlite3.connect("file:{}?mode=ro".format(hybrid_index), uri=True)
        try:
            metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        finally:
            connection.close()
        current = subprocess.run(
            [_trusted_git_executable(), "rev-parse", "HEAD^{commit}"], cwd=root,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
            env=_governed_git_environment(),
        ).stdout.strip()
        source = metadata.get("source_revision")
        index_schema_version = metadata.get("schema_version")
        schema_stale = index_schema_version != str(INDEX_SCHEMA_VERSION)
        semantic_description = json.loads(metadata.get("semantic_description", "{}"))
        if not isinstance(semantic_description, dict):
            semantic_description = {}
        result.update(
            {
                "status": (
                    "ready"
                    if source == current and not schema_stale
                    else "degraded"
                ),
                "stale": source != current or schema_stale,
                "source_revision": source,
                "current_revision": current,
                "semantic_status": metadata.get("semantic_status", "degraded"),
                "semantic_reason": metadata.get("semantic_reason", ""),
                "semantic_description": semantic_description,
                "index_schema_version": index_schema_version,
            }
        )
        if schema_stale:
            result.update(
                {
                    "semantic_status": "degraded",
                    "semantic_reason": "index_schema_mismatch",
                }
            )
        if result["semantic_status"] == "ready":
            try:
                current_description = _embedding(embedding_cache).describe()
                result["current_semantic_description"] = dict(current_description)
                mismatches = embedding_manifest_mismatches(
                    semantic_description, current_description
                )
                if mismatches:
                    result.update(
                        {
                            "semantic_status": "degraded",
                            "semantic_reason": "embedding_manifest_mismatch:"
                            + ",".join(mismatches),
                        }
                    )
            except Exception as error:
                result.update(
                    {
                        "semantic_status": "degraded",
                        "semantic_reason": "embedding_health_unavailable:{}".format(
                            type(error).__name__
                        ),
                    }
                )
        if source != current and result["semantic_status"] == "ready":
            result.update(
                {
                    "semantic_status": "degraded",
                    "semantic_reason": "source_revision_mismatch",
                }
            )
    except (OSError, sqlite3.Error, subprocess.SubprocessError, json.JSONDecodeError) as error:
        result.update(
            {
                "status": "degraded",
                "semantic_status": "degraded",
                "semantic_reason": "index_health_unavailable:{}".format(type(error).__name__),
            }
        )
    return result


def _recover_indexes(
    *,
    store: AgentMemoryStore,
    retrieval: Any,
    root: Path,
    authority_index: Path,
    hybrid_index: Path,
    embedding_cache: Path,
    recall_policy: RecallPolicy,
) -> Mapping[str, Any]:
    """Repair rebuildable projections without hiding local semantic degradation."""

    reliability = PipelineReliability(store)
    health = _index_health_for_paths(
        root=root,
        authority_index=authority_index,
        hybrid_index=hybrid_index,
        embedding_cache=embedding_cache,
        recall_policy=recall_policy,
    )
    semantic_reason = str(health.get("semantic_reason") or "")
    manifest_drift = semantic_reason.startswith("embedding_manifest_mismatch:")
    rebuild_needed = bool(
        health.get("status") != "ready"
        or health.get("stale")
        or manifest_drift
    )
    if not rebuild_needed:
        return {
            "action": (
                "current"
                if health.get("semantic_status") == "ready"
                else "degraded_lexical_available"
            ),
            "health": health,
        }
    try:
        authority_result = retrieval.authority.build("HEAD", context=recall_policy)
        hybrid_result = retrieval.build("HEAD", context=recall_policy)
        revision = str(
            hybrid_result.get("source_revision")
            or authority_result.get("source_revision")
            or "HEAD"
        )
        reliability.heartbeat("index", cursor=revision, now=_now(), status="ok")
        after = _index_health_for_paths(
            root=root,
            authority_index=authority_index,
            hybrid_index=hybrid_index,
            embedding_cache=embedding_cache,
            recall_policy=recall_policy,
        )
        return {
            "action": "rebuilt",
            "reason": semantic_reason or str(health.get("status") or "unknown"),
            "authority": authority_result,
            "hybrid": hybrid_result,
            "health": after,
        }
    except Exception as error:
        detail = "{}: {}".format(type(error).__name__, error)[:1000]
        reliability.record_error(
            "index", "index_recovery_failed", detail, "repository:" + str(root)
        )
        reliability.heartbeat("index", cursor=None, now=_now(), status="degraded")
        return {
            "action": "failed",
            "reason": detail,
            "health": _index_health_for_paths(
                root=root,
                authority_index=authority_index,
                hybrid_index=hybrid_index,
                embedding_cache=embedding_cache,
                recall_policy=recall_policy,
            ),
        }


def _offload(engine: OffloadEngine, args: argparse.Namespace) -> Any:
    command = args.offload_command
    if command == "start":
        return engine.start_task(
            task_id=args.task_id,
            goal=args.goal,
            constraints=args.constraint,
            source_ref=args.source_ref,
        )
    if command == "step":
        parsed = json.loads(args.arguments_json)
        if not isinstance(parsed, dict):
            raise ValueError("--arguments-json must be an object")
        return engine.record_tool_step(
            task_id=args.task_id,
            step_id=args.step_id,
            tool_name=args.tool,
            arguments=parsed,
            result=args.result,
            source_ref=args.source_ref,
            summary=args.summary,
            depends_on=args.depends_on,
            expected_version=args.version,
        )
    if command == "update":
        return engine.update_task(
            task_id=args.task_id,
            state=args.state_value,
            current_step_id=args.current_step_id,
            status_summary=args.summary,
            source_ref=args.source_ref,
            expected_version=args.version,
        )
    if command == "compact":
        if args.messages_file.is_symlink():
            raise ValueError("--messages-file must not be a symlink")
        raw = args.messages_file.read_bytes()
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError("--messages-file exceeds bounded size")
        messages = json.loads(raw.decode("utf-8"))
        if not isinstance(messages, list) or not all(isinstance(item, dict) for item in messages):
            raise ValueError("--messages-file must contain a JSON array of objects")
        return engine.compact_context(
            args.task_id,
            messages,
            expected_version=args.version,
            target_chars=args.target_chars,
            recent_messages=args.recent_messages,
        )
    if command == "inject":
        return {"injection": engine.build_injection(args.task_id, expected_version=args.version, max_chars=args.max_chars)}
    if command == "drill":
        return engine.drill_down(args.task_id, args.evidence_ref, expected_version=args.version)
    if command == "replay":
        return engine.replay(args.task_id, expected_version=args.version)
    raise AssertionError(command)


def _read_bounded_json(path: Path, *, max_bytes: int = 1024 * 1024) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError("JSON input must be a regular non-symlink file")
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError("JSON input exceeds bounded size")
    return json.loads(raw.decode("utf-8"))


def _configured_recall_policy(args: argparse.Namespace) -> RecallPolicy | None:
    profile = getattr(args, "recall_policy_profile", None)
    if profile == "local-work":
        return RecallPolicy.local_work(as_of=_now())
    path = getattr(args, "recall_policy_file", None)
    if path is None:
        return None
    value = _read_bounded_json(path, max_bytes=64 * 1024)
    if not isinstance(value, dict):
        raise ValueError("--recall-policy-file must contain a JSON object")
    return parse_recall_policy(value)


def _hook_receipt_identity(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("hook receipt {} is invalid".format(field))
    return value


def _hook_receipt_event_id(
    payload: Mapping[str, Any], *, session_id: str, prompt: str
) -> str:
    if payload.get("hook_event_name") != "UserPromptSubmit":
        raise ValueError("hook receipt event is unsupported")
    source_identity = next(
        (
            str(payload[key])
            for key in ("turn_id", "event_id", "hook_event_id")
            if isinstance(payload.get(key), str) and payload.get(key)
        ),
        stable_id(
            "hook-prompt",
            session_id,
            hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        ),
    )
    return stable_id("evt", session_id, "UserPromptSubmit", source_identity)


def _write_hook_receipt(
    path: Path,
    *,
    payload: Mapping[str, Any],
    result: Mapping[str, Any],
    stdout_bytes: bytes,
) -> Mapping[str, Any]:
    """Atomically persist exact request/output digests without raw hook prose."""

    session_id = _hook_receipt_identity(payload, "session_id")
    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str):
        raise ValueError("hook receipt prompt is invalid")
    event_id = _hook_receipt_event_id(
        payload, session_id=session_id, prompt=prompt
    )
    hook_output = result.get("hookSpecificOutput")
    additional_context = (
        hook_output.get("additionalContext", "")
        if isinstance(hook_output, Mapping)
        else ""
    )
    if not isinstance(additional_context, str):
        raise ValueError("hook receipt additionalContext is invalid")
    receipt = {
        "schema_version": 1,
        "created_at": _now().isoformat().replace("+00:00", "Z"),
        "session_id": session_id,
        "event_id": event_id,
        "input_prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "additional_context_sha256": hashlib.sha256(
            additional_context.encode("utf-8")
        ).hexdigest(),
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
    }
    parent = path.parent.resolve(strict=False)
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and path.is_dir():
        raise ValueError("--receipt-path must not be a directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".agent-memory-hook-receipt-", dir=str(parent)
    )
    temporary = Path(temporary_name)
    try:
        encoded = (
            json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory_descriptor = os.open(str(parent), os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return receipt


def _proposal(store: AgentMemoryStore, args: argparse.Namespace) -> Any:
    gates = _read_bounded_json(args.gates_file)
    if not isinstance(gates, dict):
        raise ValueError("--gates-file must contain a JSON object")
    plane = control_plane(args.root.resolve(strict=True))
    bridge = CandidateGovernanceBridge(store)
    if args.proposal_command == "prepare":
        return bridge.prepare(
            plane,
            candidate_id=args.candidate_id,
            destination=args.destination,
            scope=args.scope,
            applies_to=args.applies_to,
            gates=gates,
        )
    if args.proposal_command == "tombstone":
        return bridge.prepare_tombstone(
            plane,
            candidate_id=args.candidate_id,
            gates=gates,
        )
    raise AssertionError(args.proposal_command)


def _progressive(args: argparse.Namespace) -> Mapping[str, object]:
    if args.progressive_state_dir is None:
        raise ValueError("--progressive-state-dir is required")
    from progressive_host import (
        ProgressiveSessionController,
        activation_status,
        set_mode,
    )

    if args.progressive_command == "enable":
        return set_mode(args.progressive_state_dir, "candidate")
    if args.progressive_command == "rollback":
        return set_mode(args.progressive_state_dir, "legacy")
    if args.progressive_command == "status":
        return activation_status(args.progressive_state_dir)
    controller = ProgressiveSessionController(
        args.progressive_state_dir,
        root=args.root,
        codex_home=args.progressive_codex_home,
        graph_root=args.progressive_graph_root,
    )
    if args.progressive_command == "show":
        return controller.show(args.session_token)
    if args.progressive_command == "step":
        try:
            decision = json.loads(args.decision_json)
        except json.JSONDecodeError as error:
            raise ValueError("--decision-json must be a JSON object") from error
        if not isinstance(decision, dict):
            raise ValueError("--decision-json must be a JSON object")
        return controller.step(args.session_token, decision)
    raise AssertionError(args.progressive_command)


def main() -> int:
    args = parser().parse_args()
    store = AgentMemoryStore(args.state)
    if args.command == "hook":
        adapter = CodexHookAdapter(_runtime(args, store))
        try:
            raw = sys.stdin.buffer.read(MAX_HOOK_INPUT_BYTES + 1)
            if len(raw) > MAX_HOOK_INPUT_BYTES:
                raise ValueError("hook input exceeds bounded size")
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("hook input must be an object")
            result = adapter.handle(payload) or {}
        except Exception as error:
            adapter.audit_input_error("{}: {}".format(type(error).__name__, error))
            result = {}
        stdout_bytes = (
            json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")
        if args.receipt_path is not None:
            try:
                _write_hook_receipt(
                    args.receipt_path,
                    payload=payload,
                    result=result,
                    stdout_bytes=stdout_bytes,
                )
            except Exception as error:
                adapter.audit_input_error(
                    "hook_receipt_failed: {}: {}".format(type(error).__name__, error)
                )
                return 2
        sys.stdout.buffer.write(stdout_bytes)
        sys.stdout.buffer.flush()
        return 0
    try:
        reliability = PipelineReliability(store)
        if args.command == "capture":
            result = TranscriptCapture(store).capture_jsonl(args.session_id, args.transcript)
        elif args.command == "distill":
            former = CandidateFormer(store)
            receipt = former.form_candidates(args.session_id)
            result = {
                "receipt": asdict(receipt),
                "candidates": former.project_candidates(args.session_id),
            }
        elif args.command == "lifecycle":
            instant = _now()
            if args.now:
                instant = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
                if instant.tzinfo is None:
                    raise ValueError("--now must be timezone-aware")
            result = asdict(
                LifecycleResolver().resolve_store(
                    store,
                    now=instant,
                    session_id=args.session_id,
                )
            )
        elif args.command == "proposal":
            result = _proposal(store, args)
        elif args.command == "index":
            recall_policy = _configured_recall_policy(args)
            if recall_policy is None:
                raise RecallPolicyError("recall policy is required to build indexes")
            request_binding = None
            if args.query is not None:
                router_root = args.router_root or args.root
                route = route_knowledge(
                    args.query, root=router_root, profile=args.router_profile
                )
                request = verify_recall_request(
                    args.query,
                    recall_policy,
                    route_result=route,
                    entry_point="hybrid_retrieval",
                    session_id="index-build:"
                    + hashlib.sha256(
                        (
                            str(args.root.resolve(strict=False))
                            + "\0"
                            + str(router_root.resolve(strict=False))
                        ).encode("utf-8")
                    ).hexdigest(),
                )
                recall_policy = request.policy
                request_binding = request.to_mapping()
            retrieval = _retrieval(
                root=args.root,
                authority_index=args.authority_index,
                hybrid_index=args.hybrid_index,
                embedding_cache=args.embedding_cache,
            )
            authority_result = retrieval.authority.build(
                args.revision, context=recall_policy
            )
            hybrid_result = retrieval.build(args.revision, context=recall_policy)
            reliability.heartbeat(
                "index", cursor=str(hybrid_result["source_revision"]), now=_now(), status="ok"
            )
            result = {
                "authority": authority_result,
                "hybrid": hybrid_result,
                "request_binding": request_binding,
            }
        elif args.command == "recall":
            recall_policy = _configured_recall_policy(args)
            if recall_policy is None:
                result = {
                    "status": "abstained",
                    "reason": "recall_policy_missing",
                    "source_revision": None,
                    "matches": [],
                }
            else:
                query = " ".join(args.query)
                try:
                    router_root = args.router_root or args.root
                    route = route_knowledge(
                        query, root=router_root, profile=args.router_profile
                    )
                    request = verify_recall_request(
                        query,
                        recall_policy,
                        route_result=route,
                        entry_point="agent_cli",
                        session_id="agent-cli:" + hashlib.sha256(
                            (
                                str(args.root.resolve(strict=False))
                                + "\0"
                                + str(router_root.resolve(strict=False))
                            ).encode("utf-8")
                        ).hexdigest(),
                    )
                except Exception:
                    result = {
                        "status": "abstained",
                        "reason": "query_classification_failed",
                        "source_revision": None,
                        "matches": [],
                    }
                else:
                    result = _retrieval(
                        root=args.root,
                        authority_index=args.authority_index,
                        hybrid_index=args.hybrid_index,
                        embedding_cache=args.embedding_cache,
                    ).recall(
                        query,
                        context=request.policy,
                        limit=args.limit,
                        request_binding=request.to_mapping(),
                    )
            reliability.heartbeat(
                "recall", cursor=str(result.get("source_revision") or "none"), now=_now(), status=str(result.get("status"))
            )
        elif args.command == "progressive":
            result = _progressive(args)
        elif args.command == "offload":
            result = _offload(OffloadEngine(store), args)
            reliability.heartbeat("offload", cursor=args.offload_command, now=_now(), status="ok")
        elif args.command == "recover":
            result = asdict(reliability.recover(now=_now()))
            result["retention_gc"] = store.run_retention_gc(
                now=_now().isoformat().replace("+00:00", "Z"),
                request_id=None,
            )
            dispatcher = CandidateJobDispatcher(store)
            result["candidate_backfill"] = dispatcher.enqueue_missing(now=_now())
            result["distill_dispatch"] = dispatcher.dispatch_pending(
                worker_id="cli-recover",
                limit=16,
            )
            recall_policy = _configured_recall_policy(args)
            if recall_policy is None:
                result["index_recovery"] = {
                    "action": "abstained",
                    "reason": "recall_policy_missing",
                }
            else:
                result["index_recovery"] = _recover_indexes(
                    store=store,
                    retrieval=_retrieval(
                        root=args.root,
                        authority_index=args.authority_index,
                        hybrid_index=args.hybrid_index,
                        embedding_cache=args.embedding_cache,
                    ),
                    root=args.root,
                    authority_index=args.authority_index,
                    hybrid_index=args.hybrid_index,
                    embedding_cache=args.embedding_cache,
                    recall_policy=recall_policy,
                )
        elif args.command == "health":
            result = _health(store, args)
        else:
            raise AssertionError(args.command)
    except Exception as error:
        print(
            json.dumps(
                {"ok": False, "error": {"code": type(error).__name__, "message": str(error)}},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps({"ok": True, "result": _jsonable(result)}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
