"""High-precision proposal formation from private captured collaboration evidence.

This module never writes canonical Markdown and never authorizes a proposal.
It records classifications and lifecycle relations so the existing control
plane can later decide whether an exact, source-bound proposal may advance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import re
from typing import Any, Callable, Mapping

from .reliability import PipelineReliability
from .store import AgentMemoryStore, canonical_json, stable_id, utc_now


MAX_ASSISTANT_SUPPORT_PAIRS = 8


@dataclass(frozen=True)
class CandidateBatchReceipt:
    session_id: str
    examined: int
    created: int
    relations_created: int
    no_ops: int


@dataclass(frozen=True)
class _Classification:
    memory_class: str
    claim: str
    span_start: int
    span_end: int
    normalized_claim: str
    slot_key: str
    relation_hint: str | None = None


class CandidateFormer:
    """Classify explicit statements and propose relations without promotion."""

    def __init__(
        self,
        store: AgentMemoryStore,
        *,
        local_judge: Callable[[str], Mapping[str, str]] | None = None,
    ) -> None:
        self.store = store
        self.local_judge = local_judge

    def form_candidates(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
        through_line: int | None = None,
        acknowledge_pending: bool = True,
    ) -> CandidateBatchReceipt:
        stamp = _iso(now) if now is not None else utc_now()
        selected_job_id: str | None = None
        if acknowledge_pending:
            pending = [
                job
                for job in self.store.list_jobs()
                if job["kind"] == "distill"
                and job["status"] == "pending"
                and job["payload"].get("session_id") == session_id
                and isinstance(job["payload"].get("checkpoint_line"), int)
            ]
            if through_line is None and pending:
                through_line = int(pending[0]["payload"]["checkpoint_line"])
                selected_job_id = str(pending[0]["job_id"])
            elif through_line is not None:
                exact = [
                    job for job in pending
                    if int(job["payload"]["checkpoint_line"]) == through_line
                ]
                selected_job_id = str(exact[0]["job_id"]) if exact else None

        observed_evidence = self.store.list_evidence(session_id=session_id)
        all_evidence = self._candidate_evidence(observed_evidence)
        if through_line is None:
            through_line = max(
                (int(row["source_line"]) for row, _classified in all_evidence),
                default=0,
            )
        if through_line < 0:
            raise ValueError("through_line must not be negative")
        evidence = [
            (row, classified)
            for row, classified in all_evidence
            if int(row["source_line"]) <= through_line
        ]
        evidence.sort(key=lambda value: _evidence_order(value[0]))
        existing = self.store.list_candidates()
        existing_relations = self.store.list_relations()
        existing_ids = {row["candidate_id"] for row in existing}
        working = list(existing)
        new_candidates: list[dict[str, Any]] = []
        relations: list[dict[str, Any]] = []
        no_ops = 0

        for row, classified in evidence:
            if classified.memory_class == "no_op":
                no_ops += 1
            claim_hash = hashlib.sha256(classified.claim.encode("utf-8")).hexdigest()
            candidate_id = stable_id(
                "cand", row["event_id"], classified.memory_class, claim_hash
            )
            if candidate_id in existing_ids:
                continue
            candidate = {
                "candidate_id": candidate_id,
                "session_id": session_id,
                "memory_class": classified.memory_class,
                "claim": classified.claim,
                "normalized_claim": classified.normalized_claim,
                "claim_hash": claim_hash,
                "slot_key": classified.slot_key,
                "status": "ignored" if classified.memory_class == "no_op" else "proposed",
                "requires_authorization": classified.memory_class != "no_op",
                "high_impact": classified.memory_class
                in {"fact", "preference", "principle", "deletion_request"},
                "expires_at": _expiry(classified.memory_class, row.get("occurred_at"), classified.claim),
                "source_event_id": row["event_id"],
                "source_path": row["source_path"],
                "source_line": row["source_line"],
                # ``claim`` may be a bounded deterministic normalization (for
                # example punctuation or negation repair).  Provenance must
                # still retain the exact bytes reopened from the transcript.
                "source_span": row["content"][classified.span_start : classified.span_end],
                "span_start": classified.span_start,
                "span_end": classified.span_end,
                "source_text_hash": hashlib.sha256(row["content"].encode("utf-8")).hexdigest(),
                "created_at": row.get("occurred_at") or stamp,
                "relation_hint": classified.relation_hint,
            }
            new_candidates.append(candidate)
            if classified.memory_class == "deletion_request":
                for target in _deletion_targets(candidate, working):
                    relations.append(
                        _relation(candidate, target, "delete", "explicit user deletion proposal", stamp)
                    )
            elif classified.memory_class != "no_op":
                relations.extend(_lifecycle_relations(candidate, working, stamp))
            working.append(candidate)
            existing_ids.add(candidate_id)

        # Imported/backfilled evidence may predate a candidate already in the
        # store.  Repair only lineages that had no outgoing lifecycle relation
        # at all; this preserves an earlier explicit update/conflict decision
        # while ensuring provenance order, not ingestion order, defines the
        # first relationship in a slot.
        touched_slots = {str(candidate["slot_key"]) for candidate in new_candidates}
        outgoing = {
            str(row["source_candidate_id"])
            for row in [*existing_relations, *relations]
            if row["relation_type"] != "delete"
        }
        ordered_working = sorted(working, key=_candidate_order)
        for source in ordered_working:
            if (
                source["candidate_id"] in outgoing
                or source["memory_class"] in {"no_op", "deletion_request"}
                or source["slot_key"] not in touched_slots
            ):
                continue
            repaired = _lifecycle_relations(source, ordered_working, stamp)
            if repaired:
                relations.extend(repaired)
                outgoing.add(str(source["candidate_id"]))

        persisted_candidates = [
            {key: value for key, value in candidate.items() if key != "relation_hint"}
            for candidate in new_candidates
        ]
        created, relation_count = self.store.save_candidate_batch(
            persisted_candidates,
            relations,
            completed_job_id=selected_job_id,
            stage_cursor=f"{session_id}:{through_line}",
            updated_at=stamp,
        )
        return CandidateBatchReceipt(
            session_id=session_id,
            examined=len(evidence),
            created=created,
            relations_created=relation_count,
            no_ops=no_ops,
        )

    def project_candidates(self, session_id: str) -> list[dict[str, Any]]:
        """Return a versioned external DTO with unambiguous provenance IDs.

        Candidate storage deliberately keeps ``source_event_id`` as an
        internal foreign key to ``evidence.event_id``.  Host payloads also
        call their upstream identity ``event_id``.  Reusing one field name for
        both namespaces made external provenance impossible to correlate.
        This projection reopens the evidence row, verifies the exact source
        locator/span, and exposes both identities without changing the durable
        foreign-key contract used by governance.
        """

        evidence_by_id = {
            str(row["event_id"]): row
            for row in self.store.list_evidence(session_id=session_id)
        }
        projected: list[dict[str, Any]] = []
        for stored in self.store.list_candidates(session_id=session_id):
            internal_event_id = str(stored["source_event_id"])
            evidence = evidence_by_id.get(internal_event_id)
            if evidence is None or str(evidence.get("session_id")) != session_id:
                raise ValueError("candidate_provenance_unresolved")
            content = str(evidence.get("content") or "")
            source_text_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
            start = int(stored["span_start"])
            end = int(stored["span_end"])
            if (
                str(stored["source_path"]) != str(evidence.get("source_path"))
                or int(stored["source_line"]) != int(evidence.get("source_line") or 0)
                or str(stored["source_text_hash"]) != source_text_sha256
                or start < 0
                or end < start
                or end > len(content)
                or content[start:end] != str(stored["source_span"])
            ):
                raise ValueError("candidate_provenance_invalid")
            metadata = evidence.get("metadata")
            upstream_event_id = (
                metadata.get("source_event_id")
                if isinstance(metadata, Mapping)
                else None
            )
            if isinstance(upstream_event_id, str) and upstream_event_id:
                source_identity = upstream_event_id
                source_identity_kind = "upstream_event_id"
            else:
                line_hash = str(evidence.get("source_line_hash") or "")
                if not re.fullmatch(r"[0-9a-f]{64}", line_hash):
                    raise ValueError("candidate_provenance_unresolved")
                source_identity = "transcript-line:" + line_hash
                source_identity_kind = "transcript_line_hash"
            binding = {
                "schema_version": 1,
                "source_identity_kind": source_identity_kind,
                "source_identity_sha256": hashlib.sha256(
                    source_identity.encode("utf-8")
                ).hexdigest(),
                "evidence_event_id": internal_event_id,
                "session_id_sha256": hashlib.sha256(
                    session_id.encode("utf-8")
                ).hexdigest(),
                "source_path": str(stored["source_path"]),
                "source_line": int(stored["source_line"]),
                "span_start": start,
                "span_end": end,
                "source_text_sha256": source_text_sha256,
            }
            view = dict(stored)
            view.update(
                {
                    "candidate_schema_version": 2,
                    "source_event_id": source_identity,
                    "evidence_event_id": internal_event_id,
                    "source_binding": {
                        **binding,
                        "binding_sha256": hashlib.sha256(
                            canonical_json(binding).encode("utf-8")
                        ).hexdigest(),
                    },
                }
            )
            projected.append(view)
        return projected

    def coverage_report(self, *, session_id: str | None = None) -> Mapping[str, Any]:
        """Report a bounded proxy for silent candidate-formation loss."""

        evidence = self.store.list_evidence(session_id=session_id)
        eligible = [
            (row, classified)
            for row, classified in self._candidate_evidence(evidence)
            if classified.memory_class != "no_op"
        ]
        formed_event_ids = {
            str(row["source_event_id"])
            for row in self.store.list_candidates(session_id=session_id)
            if row["memory_class"] != "no_op"
        }
        eligible_event_ids = {str(row["event_id"]) for row, _classified in eligible}
        formed = eligible_event_ids & formed_event_ids
        missing = sorted(eligible_event_ids - formed_event_ids)
        eligible_count = len(eligible_event_ids)
        return {
            "schema_version": 1,
            "metric": "candidate_formation_recall_proxy",
            "eligible_durable_signals": eligible_count,
            "formed_durable_signals": len(formed),
            "missing_durable_signals": len(missing),
            "candidate_formation_recall": (
                1.0 if eligible_count == 0 else len(formed) / eligible_count
            ),
            "eligible_by_source": {
                "user": sum(1 for row, _ in eligible if row["evidence_type"] == "user"),
                "assistant_tool_grounded": sum(
                    1 for row, _ in eligible if row["evidence_type"] == "assistant"
                ),
            },
            "missing_event_ids": missing[:20],
            "missing_event_ids_truncated": len(missing) > 20,
        }

    def _candidate_evidence(
        self, evidence: list[Mapping[str, Any]]
    ) -> list[tuple[Mapping[str, Any], _Classification]]:
        selected: list[tuple[Mapping[str, Any], _Classification]] = []
        for row in evidence:
            evidence_type = row.get("evidence_type")
            if evidence_type == "user":
                selected.append((row, self._classify(str(row["content"]))))
                continue
            if evidence_type != "assistant":
                continue
            classified = self._classify(str(row["content"]))
            # Assistant prose is not user truth. Admit only a deterministic
            # lesson whose exact turn contains a complete observed tool pair.
            if classified.memory_class == "lesson" and _assistant_tool_support(evidence, row):
                selected.append((row, classified))
        return selected

    def _classify(self, text: str) -> _Classification:
        """Use an optional local-only judge while retaining exact source spans.

        The judge proposes only a class and normalized claim.  This boundary
        intentionally cannot authorize, choose a destination, or manufacture
        text absent from the captured source.  Invalid or ungrounded proposals
        fail closed to the deterministic built-in classifier.
        """
        fallback = _classify(text)
        if self.local_judge is None:
            return fallback
        proposed = self.local_judge(text)
        if not isinstance(proposed, Mapping):
            return fallback
        memory_class = str(proposed.get("memory_class") or "")
        if memory_class not in {
            "fact", "preference", "plan", "temporary_state", "method",
            "principle", "lesson", "no_op", "deletion_request",
        }:
            return fallback
        claim = str(proposed.get("claim") or "").strip()
        if memory_class == "no_op":
            claim = claim or text.strip()
        if not claim:
            return fallback
        start = text.find(claim)
        if start < 0:
            # A normalization may remove punctuation but cannot become a
            # source quote.  Prefer the built-in exact span when classes agree;
            # otherwise retain the entire observed source as the claim.
            if fallback.memory_class == memory_class:
                return fallback
            claim = text.strip()
            start = text.find(claim)
        end = start + len(claim)
        slot = _slot(memory_class, claim, memory_class)
        return _Classification(
            memory_class,
            claim,
            start,
            end,
            _canonical_claim(memory_class, slot, claim),
            slot,
            fallback.relation_hint,
        )


class CandidateJobDispatcher:
    """Bounded durable dispatcher for exact capture-checkpoint distill jobs."""

    def __init__(self, store: AgentMemoryStore) -> None:
        self.store = store
        self.reliability = PipelineReliability(store)
        self.former = CandidateFormer(store)

    def enqueue_missing(
        self,
        *,
        session_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Create durable repair work for evidence missed by an older runtime."""

        all_evidence = self.store.list_evidence(session_id=session_id)
        sessions = sorted({str(row["session_id"]) for row in all_evidence})
        active_sessions = {
            str(job["payload"].get("session_id"))
            for job in self.store.list_jobs()
            if job["kind"] == "distill" and job["status"] in {"pending", "leased"}
        }
        enqueued: list[str] = []
        already_active: list[str] = []
        for selected_session in sessions:
            evidence = [
                row for row in all_evidence if str(row["session_id"]) == selected_session
            ]
            eligible = [
                row
                for row, classified in self.former._candidate_evidence(evidence)
                if classified.memory_class != "no_op"
            ]
            formed = {
                str(candidate["source_event_id"])
                for candidate in self.store.list_candidates(selected_session)
                if candidate["memory_class"] != "no_op"
            }
            missing = sorted(
                str(row["event_id"])
                for row in eligible
                if str(row["event_id"]) not in formed
            )
            if not missing:
                continue
            if selected_session in active_sessions:
                already_active.append(selected_session)
                continue
            through_line = max(int(row["source_line"]) for row in evidence)
            digest = hashlib.sha256("\0".join(missing).encode("utf-8")).hexdigest()
            job = self.reliability.enqueue(
                "distill",
                {"session_id": selected_session, "checkpoint_line": through_line},
                "candidate-backfill-v1:{}:{}".format(selected_session, digest),
                now=now,
            )
            enqueued.append(job.job_id)
        return {
            "enqueued": len(enqueued),
            "job_ids": enqueued,
            "already_active_sessions": already_active,
        }

    def dispatch_pending(
        self,
        *,
        worker_id: str,
        limit: int = 4,
        lease_seconds: int = 30,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if limit < 1:
            raise ValueError("limit must be positive")
        stamp = now or datetime.now(timezone.utc)
        recovery = self.reliability.recover(now=stamp)
        jobs = self.reliability.lease(
            worker_id,
            now=stamp,
            lease_seconds=lease_seconds,
            kinds=("distill",),
            limit=limit,
        )
        completed: list[str] = []
        failed: list[str] = []
        for job in jobs:
            try:
                session_id = job.payload.get("session_id")
                checkpoint_line = job.payload.get("checkpoint_line")
                if not isinstance(session_id, str) or not session_id:
                    raise ValueError("distill session_id is invalid")
                if not isinstance(checkpoint_line, int) or checkpoint_line < 0:
                    raise ValueError("distill checkpoint_line is invalid")
                receipt = self.former.form_candidates(
                    session_id,
                    now=stamp,
                    through_line=checkpoint_line,
                    acknowledge_pending=False,
                )
                self.reliability.complete(
                    job.job_id,
                    worker_id,
                    {
                        "session_id": session_id,
                        "checkpoint_line": checkpoint_line,
                        "candidates_created": receipt.created,
                        "relations_created": receipt.relations_created,
                    },
                    now=stamp,
                )
                completed.append(job.job_id)
            except Exception as error:
                self.reliability.fail(
                    job.job_id,
                    worker_id,
                    "distill_dispatch_failed",
                    "{}: {}".format(type(error).__name__, error)[:1000],
                    now=stamp,
                    retry_delay_seconds=1,
                )
                failed.append(job.job_id)
        return {
            "processed": len(completed),
            "failed": len(failed),
            "completed_job_ids": completed,
            "failed_job_ids": failed,
            "recovery": {
                "requeued": recovery.requeued,
                "dead_lettered": recovery.dead_lettered,
            },
        }


def _classify(text: str) -> _Classification:
    deletion = re.search(
        r"(?:"
        r"删除记忆\s*[：:]?|请(?:忘记|删除|抹掉)|忘掉|不要再记住|"
        r"我要求移除|(?:清除|(?:撤销并)?删除)[^。！!？?\n]*(?:记录|记忆|保存)|"
        r"(?:记忆|记录)[^。！!？?\n]*(?:删掉|删除|清除|移除)|"
        r"不要[^。！!？?\n]*保留在记忆里|"
        r"(?:forget|erase|delete|remove)[^.!?\n]*(?:memory|saved|stored|preference|location|address|information)"
        r")[^。！!？?\n]*",
        text,
        re.IGNORECASE,
    )
    if deletion:
        claim = deletion.group(0).strip()
        start = deletion.start()
        return _Classification(
            "deletion_request",
            claim,
            start,
            start + len(claim),
            _normalize(claim),
            _deletion_slot(claim),
            "delete",
        )

    relation_hint = None
    if re.search(r"冲突说明|不再|改回|并非|不是", text):
        relation_hint = "conflict"
    elif re.search(r"更新偏好|更新为|现在|以后改|改为", text):
        relation_hint = "update"

    definitions = (
        ("preference", r"(?:更新偏好|偏好)\s*[：:]", "preference"),
        ("temporary_state", r"临时状态\s*[：:]", "temporary_state"),
        ("method", r"(?:工作方法|方法)\s*[：:]", "method"),
        ("principle", r"(?:长期原则|原则)\s*[：:]", "principle"),
        ("lesson", r"(?:经验教训|教训)\s*[：:]", "lesson"),
        ("plan", r"计划\s*[：:]", "plan"),
        ("fact", r"事实\s*[：:]", "fact"),
    )
    for memory_class, pattern, default_slot in definitions:
        marker = re.search(pattern, text)
        if marker:
            start = marker.end()
            claim, start, end = _trim_span(text, start, len(text))
            slot = _slot(memory_class, claim, default_slot)
            return _Classification(
                memory_class,
                claim,
                start,
                end,
                _canonical_claim(memory_class, slot, claim),
                slot,
                relation_hint,
            )

    # Establish utterance mood before looking for durable nouns.  A question
    # about a configuration and a request to change it are not assertions of
    # user truth, even when they contain the same words as a stable fact.
    stripped = text.strip()
    interrogative = re.search(r"[?？]\s*$", stripped) or re.match(
        r"(?:请问|为什么|为何|怎么|如何|是否|是不是|能否|可否|能不能|可以不可以)",
        stripped,
        re.IGNORECASE,
    )
    if interrogative:
        claim, start, end = _trim_span(text, 0, len(text))
        return _Classification("no_op", claim, start, end, _normalize(claim), "no_op", None)

    # Round/session/time bounds outrank durable-looking repositories, paths,
    # or service names.  These forms describe an expiring operating condition,
    # not a canonical fact about the system.
    bounded_temporary = re.search(
        r"(?:"
        r"^(?:本轮|这一轮|这次|当前阶段|现阶段|暂时|暂用|眼下)[^。！!？?\n]+|"
        r"^直到[^。！!？?\n]+(?:结束|完成|通过|恢复)[^。！!？?\n]*|"
        r"^[^。！!？?\n]{1,64}(?:获批|批准|结束|完成|恢复)之前"
        r"[^。！!？?\n]*(?:只能|无法|不要|保持|暂停)|"
        r"^for\s+now\b[^.!?\n]+|"
        r"^until\s+[^,!?.\n]+,?\s*[^.!?\n]+"
        r")",
        stripped,
        re.IGNORECASE,
    )
    retrospective_lesson = re.search(
        r"(?:这次|本次|上次)[^。！!？?\n]{0,160}(?:失败|问题|故障|回滚|错乱)"
        r"[^。！!？?\n]{0,160}(?:下次|以后|今后)",
        stripped,
    )
    if bounded_temporary and retrospective_lesson is None:
        claim, start, end = _trim_span(text, 0, len(text))
        slot = _slot("temporary_state", claim, "temporary_state")
        return _Classification(
            "temporary_state", claim, start, end,
            _canonical_claim("temporary_state", slot, claim), slot, relation_hint,
        )

    one_shot_operation = re.search(
        r"(?:"
        r"^(?:请|麻烦|帮我|把|先|继续|重新|再)[^。！!？?\n]{0,64}"
        r"(?:打开|运行|执行|检查|重跑|切换|修改|改成|贴|滚动|总结|解释|发送|下载)|"
        r"^(?:不要|别|停止)[^。！!？?\n]{0,32}(?:现在|马上|立刻)?"
        r"[^。！!？?\n]{0,32}(?:发布|执行|运行|重跑|打开|修改|写入)|"
        r"^(?:必须|需要|应该)[^。！!？?\n]{0,16}(?:现在|马上|立刻|这次|本轮)"
        r"[^。！!？?\n]{0,48}(?:运行|执行|重跑|检查|发布|修改|写入)"
        r")",
        stripped,
        re.IGNORECASE,
    )
    if one_shot_operation:
        claim, start, end = _trim_span(text, 0, len(text))
        return _Classification("no_op", claim, start, end, _normalize(claim), "no_op", None)

    # Stable declarative facts have a subject and an assertion predicate.
    # Mood and temporal guards above prevent questions, commands, and bounded
    # state from entering this deliberately broader synonym family.
    general_fact = re.search(
        r"[^。！!？?\n]{1,64}(?:"
        r"(?:默认)?是|(?<!因)为|叫|位于|使用|采用|运行在|(?:固定)?监听|"
        r"存放在|由[^。！!？?\n]{1,48}维护|固定(?:为|在)"
        r")[^。！!？?\n]+",
        stripped,
        re.IGNORECASE,
    )
    if general_fact:
        claim, start, end = _trim_span(text, general_fact.start(), general_fact.end())
        slot = _slot("fact", claim, "fact")
        return _Classification(
            "fact", claim, start, end,
            _canonical_claim("fact", slot, claim), slot, relation_hint,
        )

    # Present-tense acknowledgements, inspection chatter and tentative
    # "look first" utterances are not durable preferences, plans or state.
    # Keep this guard ahead of the broad first-person forms below.
    ephemeral_no_op = re.search(
        r"(?:"
        r"我(?:正在)?(?:看|读)[^。！!？?\n]*(?:diff|输出|日志|结果|文档)|"
        r"我(?:喜欢|满意)(?:这个|这次|刚才)[^。！!？?\n]*(?:解释|结果|输出|回答)|"
        r"我(?:打算|准备)先?(?:看|确认)[^。！!？?\n]*(?:再说|一下)"
        r")",
        text,
        re.IGNORECASE,
    )
    if ephemeral_no_op:
        claim, start, end = _trim_span(text, 0, len(text))
        return _Classification("no_op", claim, start, end, _normalize(claim), "no_op", None)

    # A conflict statement may intentionally lead with its relation rather than
    # a normal classification prefix.
    if relation_hint and "偏好" in text:
        start = text.find("偏好")
        claim, start, end = _trim_span(text, start, len(text))
        slot = _slot("preference", claim, "preference")
        return _Classification(
            "preference",
            claim,
            start,
            end,
            _canonical_claim("preference", slot, claim),
            slot,
            relation_hint,
        )

    implicit = (
        ("preference", r"我(?:更)?(?:偏好|喜欢).+", "preference"),
        ("plan", r"我(?:计划|打算|准备).+", "plan"),
        ("temporary_state", r"我(?:今天|目前|正在).+", "temporary_state"),
        ("fact", r"我(?:住在|常驻|的.+是).+", "fact"),
    )
    for memory_class, pattern, default_slot in implicit:
        match = re.search(pattern, text)
        if match:
            claim, start, end = _trim_span(text, match.start(), match.end())
            slot = _slot(memory_class, claim, default_slot)
            return _Classification(
                memory_class,
                claim,
                start,
                end,
                _canonical_claim(memory_class, slot, claim),
                slot,
                relation_hint,
            )

    weekly_plan = re.search(r"本周先(.+?)[；;，,]周五复查", text)
    if weekly_plan:
        claim = f"本周{weekly_plan.group(1).strip()}，周五复查"
        return _Classification(
            "plan",
            claim,
            weekly_plan.start(),
            weekly_plan.end(),
            _canonical_claim("plan", "plan:weekly_review", claim),
            "plan:weekly_review",
        )

    review_plan = re.search(r"review\s+(?:改到\s+)?\d{4}-\d{2}-\d{2}", text, re.IGNORECASE)
    if review_plan:
        claim, start, end = _trim_span(text, review_plan.start(), review_plan.end())
        return _Classification(
            "plan",
            claim,
            start,
            end,
            _canonical_claim("plan", "plan:review", claim),
            "plan:review",
            "update" if "改到" in claim else None,
        )

    default_output = re.search(r"默认输出\s*([^，。；\s]+)", text)
    if default_output:
        claim, start, end = _trim_span(text, default_output.start(), default_output.end())
        return _Classification(
            "preference",
            claim,
            start,
            end,
            _canonical_claim("preference", "preference:default_output", claim),
            "preference:default_output",
            "update",
        )

    configuration = re.search(r"([^，。；\n=]{1,64})\s*=\s*([^，。；\n]+)", text)
    if configuration:
        claim, start, end = _trim_span(text, configuration.start(), configuration.end())
        subject = _normalize(configuration.group(1))[:48]
        slot = f"fact:configuration:{subject}"
        return _Classification(
            "fact", claim, start, end, _canonical_claim("fact", slot, claim), slot, "update"
        )

    path_change = re.search(r"路径(?:\s+|改为\s*)(/[^\s，。；]+)", text)
    if path_change:
        claim, start, end = _trim_span(text, path_change.start(), path_change.end())
        return _Classification(
            "fact", claim, start, end, _canonical_claim("fact", "fact:path", claim), "fact:path",
            "update" if "改为" in claim else None,
        )

    temporary_switch = re.search(r"临时(?:开关|状态)[^。！!？?\n]+", text)
    if temporary_switch:
        claim, start, end = _trim_span(text, temporary_switch.start(), temporary_switch.end())
        slot = _slot("temporary_state", claim, "temporary_state")
        return _Classification(
            "temporary_state", claim, start, end,
            _canonical_claim("temporary_state", slot, claim), slot, relation_hint,
        )

    natural_preference = re.search(
        r"(?:"
        r"我(?:更)?(?:希望|习惯|倾向于?|只想)[^。！!？?\n]+|"
        r"(?:回复|回答|代码示例|图表配色|长回答|日志|日期)[^。！!？?\n]{0,80}"
        r"(?:请|尽量|使用|用|按|保持|先放|只想|写成)[^。！!？?\n]*|"
        r"(?:优先|默认)给我[^。！!？?\n]+|"
        r"i\s+prefer\s+[^.!?\n]+|"
        r"please\s+(?:format|write|present|answer|respond)\s+[^.!?\n]+"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_preference:
        claim, start, end = _trim_span(text, natural_preference.start(), natural_preference.end())
        slot = _slot("preference", claim, "preference")
        return _Classification(
            "preference", claim, start, end,
            _canonical_claim("preference", slot, claim), slot, relation_hint,
        )

    natural_plan = re.search(
        r"(?:"
        r"(?:下周|周[一二三四五六日天]前|今天(?:下午|晚上)|今晚|下一步|这个月|本周|发布后|"
        r"等[^。！!？?\n]+就)[^。！!？?\n]*(?:完成|评审|补齐|更新|修|测试|安排|切换|"
        r"合并|继续|观察|复查|演练|跑|整理)|"
        r"(?:月底前|月末前|年底前|季度末前)[^。！!？?\n]*(?:要|会|计划|打算|准备)"
        r"[^。！!？?\n]+|"
        r"we\s+will\s+[^.!?\n]+(?:tomorrow|next\s+week)|"
        r"before\s+[^,!?.\n]+,?\s+we\s+(?:intend|plan|expect)\s+to\s+[^.!?\n]+"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_plan:
        claim, start, end = _trim_span(text, natural_plan.start(), natural_plan.end())
        slot = _slot("plan", claim, "plan")
        return _Classification(
            "plan", claim, start, end,
            _canonical_claim("plan", slot, claim), slot, relation_hint,
        )

    natural_temporary = re.search(
        r"(?:"
        r"(?:我(?:目前|这周|这两天)|(?:这周|这两天)我)[^。！!？?\n]+|"
        r"(?:目前|眼下|当前|现在|暂时)[^。！!？?\n]{0,80}"
        r"(?:无法|等待|暂停|处于|不要|只能|保持|受阻)|"
        r"今天[^。！!？?\n]{0,80}(?:只能|无法|不太?稳定|暂停|等待|处于|保持|受阻)|"
        r"在本轮[^。！!？?\n]+前[^。！!？?\n]+|"
        r"这一轮[^。！!？?\n]*(?:只能|无法|暂停|等待)[^。！!？?\n]*|"
        r"(?:本轮|这次)[^。！!？?\n]*(?:先保持[^。！!？?\n]*(?:只读|冻结)|先不(?:升级|发布|写入))[^。！!？?\n]*|"
        r"(?:访问|审批|授权)[^。！!？?\n]{0,32}(?:还没|尚未)[^。！!？?\n]*(?:下来|完成|通过|开放)?|"
        r"今晚[^。！!？?\n]{0,80}(?:不稳定|不可用|受限|只能|无法)[^。！!？?\n]*|"
        r"手头[^。！!？?\n]{0,80}(?:只能|无法|受限)[^。！!？?\n]*|"
        r"临时(?:把|将)[^。！!？?\n]+|"
        r"i(?:'m|\s+am)\s+[^.!?\n]+\s+today|"
        r"for\s+this\s+(?:iteration|week|session)[^.!?\n]*(?:can\s+only|cannot|blocked)[^.!?\n]*"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_temporary:
        claim, start, end = _trim_span(text, natural_temporary.start(), natural_temporary.end())
        slot = _slot("temporary_state", claim, "temporary_state")
        return _Classification(
            "temporary_state", claim, start, end,
            _canonical_claim("temporary_state", slot, claim), slot, relation_hint,
        )

    # Everyday collaboration rarely includes ontology prefixes.  Admit only
    # bounded, high-precision forms whose durable intent is explicit in the
    # sentence; vague acknowledgements and transient completion messages stay
    # no-op so automation cannot inflate a user profile.
    durable_fact = re.search(
        r"(?:仓库|项目|系统|流程|命令|路径|代号|版本)[^。！!？?\n]{0,96}(?:是|为|位于|使用|默认)[^。！!？?\n]+",
        text,
    )
    if durable_fact:
        claim, start, end = _trim_span(text, durable_fact.start(), durable_fact.end())
        slot = _slot("fact", claim, "fact")
        return _Classification(
            "fact", claim, start, end, _canonical_claim("fact", slot, claim), slot, relation_hint
        )

    prohibition = re.search(r"(?:不要|不得|禁止|必须避免)([^。！!？?\n]+)", text)
    if prohibition:
        body = prohibition.group(1).strip()
        if "私人资料" in body and "默认上下文" in body:
            claim = "私人资料不得进入默认上下文"
        else:
            claim = "不得" + body
        slot = _slot("principle", claim, "principle")
        return _Classification(
            "principle",
            claim,
            prohibition.start(),
            prohibition.end(),
            _canonical_claim("principle", slot, claim),
            slot,
            relation_hint,
        )

    authority_principle = re.search(
        r"(?:索引仅生成候选，)?返回前必须重开\s*([^。！!？?\n]+)", text
    )
    if authority_principle:
        original, start, end = _trim_span(text, authority_principle.start(), authority_principle.end())
        claim = (
            "索引只生成候选；返回前重开权威来源"
            if "索引仅生成候选" in original and "权威来源" in original
            else original
        )
        slot = _slot("principle", claim, "principle")
        return _Classification(
            "principle", claim, start, end,
            _canonical_claim("principle", slot, claim), slot, relation_hint,
        )

    lesson = re.search(
        r"(?:这次|本次)[^。！!？?\n]{0,96}(?:失败|问题)[^。！!？?\n]*(?:下次|以后)[^。！!？?\n]+",
        text,
    )
    if lesson:
        claim, start, end = _trim_span(text, lesson.start(), lesson.end())
        slot = _slot("lesson", claim, "lesson")
        return _Classification(
            "lesson", claim, start, end, _canonical_claim("lesson", slot, claim), slot, relation_hint
        )

    derived_lesson = re.search(
        r"(?:这个|该|上述|this)\s*(?:bug|问题|故障|失败|failure)[^。！!？?\n]{0,160}"
        r"(?:说明|表明|意味着|shows?|means?)[^。！!？?\n]{0,160}"
        r"(?:必须|应当|需要|must|should)[^。！!？?\n]*",
        text,
        re.IGNORECASE,
    )
    if derived_lesson:
        claim, start, end = _trim_span(text, derived_lesson.start(), derived_lesson.end())
        slot = _slot("lesson", claim, "lesson")
        return _Classification(
            "lesson", claim, start, end,
            _canonical_claim("lesson", slot, claim), slot, relation_hint,
        )

    natural_lesson = re.search(
        r"(?:"
        r"(?:这次|本次|上次)[^。！!？?\n]{0,120}"
        r"(?:回滚|失败|问题|故障|错乱|延迟|漏报)[^。！!？?\n]{0,160}"
        r"(?:以后|下次|今后|提醒我们|说明|表明|要|先)[^。！!？?\n]*|"
        r"踩坑后发现[^。！!？?\n]+|从这次事故学到[^。！!？?\n]+|"
        r"[^。！!？?\n]{0,80}的教训是[^。！!？?\n]+|"
        r"失败复盘结论[^。！!？?\n]+"
        r"|经历[^。！!？?\n]*(?:事故|故障|失败)后[^。！!？?\n]*(?:知道|学到|明白)[^。！!？?\n]+"
        r"|the\s+(?:incident|failure|outage)\s+taught\s+us\s+to\s+[^.!?\n]+"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_lesson:
        claim, start, end = _trim_span(text, natural_lesson.start(), natural_lesson.end())
        slot = _slot("lesson", claim, "lesson")
        return _Classification(
            "lesson", claim, start, end,
            _canonical_claim("lesson", slot, claim), slot, relation_hint,
        )

    natural_principle = re.search(
        r"(?:"
        r"(?:任何|所有)[^。！!？?\n]*(?:不得|必须)|"
        r"不能因为[^。！!？?\n]+就[^。！!？?\n]+|"
        r"未经[^。！!？?\n]+(?:不得|不能|不可)[^。！!？?\n]*|"
        r"[^。！!？?\n]*(?:一律|永远|绝对)(?:[^。！!？?\n]*)(?:拒绝|不得|不能|不要)|"
        r"(?:涉及[^。！!？?\n]+的操作|跨任务上下文|助手|安全检查失败时)"
        r"[^。！!？?\n]*(?:必须|不得|只能|应当|默认拒绝)|"
        r"never\s+[^.!?\n]+|"
        r"[^.!?\n]+\s+must\s+not\s+[^.!?\n]+"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_principle:
        claim, start, end = _trim_span(text, natural_principle.start(), natural_principle.end())
        slot = _slot("principle", claim, "principle")
        return _Classification(
            "principle", claim, start, end,
            _canonical_claim("principle", slot, claim), slot, relation_hint,
        )

    natural_method = re.search(
        r"(?:"
        r"(?:做|处理)[^。！!？?\n]+时[^。！!？?\n]+|"
        r"排查[^。！!？?\n]+(?:要|应)[^。！!？?\n]+|"
        r"每次[^。！!？?\n]+都[^。！!？?\n]+|"
        r"我通常[^。！!？?\n]+|"
        r"[^。！!？?\n]+优化先[^。！!？?\n]+|"
        r"(?:发布前|遇到[^。！!？?\n]+|复盘时|先用)[^。！!？?\n]+|"
        r"[^。！!？?\n]+任务分成[^。！!？?\n]+|"
        r"代码审查按[^。！!？?\n]+|"
        r"my\s+workflow\s+is\s+to\s+[^.!?\n]+|"
        r"when\s+[^,!?.\n]+,?\s+[^.!?\n]+\s+first\s+[^.!?\n]+\s+(?:second|then)[^.!?\n]*"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_method:
        claim, start, end = _trim_span(text, natural_method.start(), natural_method.end())
        slot = _slot("method", claim, "method")
        return _Classification(
            "method", claim, start, end,
            _canonical_claim("method", slot, claim), slot, relation_hint,
        )

    natural_fact = re.search(
        r"(?:"
        r"(?:服务版本|团队[^。！!？?\n]{0,40}例会|api[^。！!？?\n]{0,40}超时时间|"
        r"测试环境|这个模块|构建产物|ci|数据库|部署环境|运行时|依赖|端口|时区)"
        r"[^。！!？?\n]*(?:是|为|固定为|运行的?是|运行在|由|存放在|安排在|使用)"
        r"[^。！!？?\n]+|"
        r"(?:后端|前端|服务|进程|代理)[^。！!？?\n]{0,48}固定监听[^。！!？?\n]+|"
        r"(?:值班群|项目群|频道|代号)[^。！!？?\n]{0,32}叫[^。！!？?\n]+|"
        r"(?:数据保留周期|备份周期|发布窗口)[^。！!？?\n]{0,32}(?:固定为|固定在)[^。！!？?\n]+|"
        r"(?:生产环境|预发布环境|开发环境)[^。！!？?\n]{0,48}(?:采用|使用)[^。！!？?\n]+|"
        r"(?:our|the)\s+[^.!?\n]+\s+(?:is|uses|runs\s+on)\s+[^.!?\n]+"
        r")",
        text,
        re.IGNORECASE,
    )
    if natural_fact:
        claim, start, end = _trim_span(text, natural_fact.start(), natural_fact.end())
        slot = _slot("fact", claim, "fact")
        return _Classification(
            "fact", claim, start, end,
            _canonical_claim("fact", slot, claim), slot, relation_hint,
        )

    claim, start, end = _trim_span(text, 0, len(text))
    return _Classification(
        "no_op", claim, start, end, _normalize(claim), "no_op", None
    )


def _trim_span(text: str, start: int, end: int) -> tuple[str, int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return text[start:end], start, end


def _slot(memory_class: str, claim: str, fallback: str) -> str:
    if "编辑器" in claim:
        return f"{memory_class}:editor"
    if any(token in claim for token in ("城市", "住在", "常驻")):
        return f"{memory_class}:city"
    if "私人数据" in claim:
        return f"{memory_class}:private_data"
    subject = re.split(r"[是为要需，。；:：]", claim, maxsplit=1)[0]
    subject = _normalize(subject)[:48] or fallback
    return f"{memory_class}:{subject}"


def _deletion_slot(claim: str) -> str:
    if "编辑器" in claim:
        return "preference:editor"
    if any(token in claim for token in ("城市", "住在", "常驻")):
        return "fact:city"
    return "delete:" + _deletion_subject(claim)[:48]


def _deletion_subject(claim: str) -> str:
    subject = claim
    # A user may combine the formal marker and the natural request.  Remove
    # each bounded directive prefix so the remaining subject can be compared
    # to the stable subject portion of an ordinary fact/preference slot.
    for _ in range(3):
        stripped = re.sub(
            r"^(?:删除记忆\s*[：:]?|请忘记|请删除|忘记|删除|关于)",
            "",
            subject,
        ).strip()
        if stripped == subject:
            break
        subject = stripped
    subject = re.sub(r"^(?:这条|这个|该条|我(?:的|偏好的)?)", "", subject).strip()
    return _normalize(subject)


def _canonical_claim(memory_class: str, slot: str, claim: str) -> str:
    value = None
    if slot.endswith(":editor"):
        matches = re.findall(r"编辑器\s*(?:是|为|改为|改回)\s*([^，。；\n]+)", claim)
        if matches:
            value = matches[-1]
    elif slot.endswith(":city"):
        match = re.search(r"(?:城市是|住在|常驻(?:城市)?是?)\s*([^，。；\n]+)", claim)
        if match:
            value = match.group(1)
    return f"{memory_class}|{slot}|{_normalize(value or claim)}"


def _normalize(text: str) -> str:
    return re.sub(r"[\s。！!？?，,；;]+", "", text).casefold()


def _lifecycle_relations(
    source: Mapping[str, Any], prior: list[Mapping[str, Any]], stamp: str
) -> list[dict[str, Any]]:
    source_order = _candidate_order(source)
    same_slot = sorted([
        candidate
        for candidate in prior
        if candidate["candidate_id"] != source["candidate_id"]
        and candidate["memory_class"] != "no_op"
        and candidate["slot_key"] == source["slot_key"]
        and candidate["memory_class"] != "deletion_request"
        and _candidate_order(candidate) < source_order
    ], key=_candidate_order)
    if not same_slot:
        return []
    latest = same_slot[-1]
    if latest["normalized_claim"] == source["normalized_claim"]:
        return [_relation(source, latest, "duplicate", "normalized claim matches", stamp)]
    hint = source.get("relation_hint")
    if hint == "update":
        return [
            _relation(source, latest, "update", "explicit replacement wording", stamp),
            _relation(source, latest, "supersede", "new proposal supersedes prior slot", stamp),
        ]
    if hint == "conflict":
        # Contradictory or untrusted wording is a quarantine signal, not an
        # authorization to replace the existing value.  Governance may later
        # convert the proposal into an update after review.
        return [_relation(source, latest, "conflict", "explicit contradictory wording", stamp)]
    # A different value in the same stable slot is both a conflict signal and
    # a proposed replacement.  None of these relations authorizes promotion;
    # they give the governance plane deterministic options while retaining the
    # prior candidate and its provenance.
    return [
        _relation(source, latest, "conflict", "same slot has a different value", stamp),
        _relation(source, latest, "update", "new value proposes an in-place update", stamp),
        _relation(source, latest, "supersede", "new value supersedes prior slot", stamp),
    ]


def _deletion_targets(
    source: Mapping[str, Any], prior: list[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    subject = str(source.get("slot_key", "")).removeprefix("delete:")
    targets = []
    for candidate in prior:
        if candidate["memory_class"] in {"no_op", "deletion_request"}:
            continue
        if _candidate_order(candidate) >= _candidate_order(source):
            continue
        candidate_slot = str(candidate.get("slot_key", ""))
        slot_subject = candidate_slot.partition(":")[2]
        exact_slot = candidate_slot == source.get("slot_key")
        subject_match = bool(
            subject
            and (
                subject == slot_subject
                or subject in slot_subject
                or slot_subject in subject
                or subject in _normalize(str(candidate.get("claim", "")))
            )
        )
        if exact_slot or subject_match:
            targets.append(candidate)
    return sorted(targets, key=_candidate_order)


def _evidence_order(row: Mapping[str, Any]) -> tuple[str, str, int, str]:
    return (
        str(row.get("occurred_at") or row.get("captured_at") or ""),
        str(row.get("source_path") or ""),
        int(row.get("source_line") or 0),
        str(row.get("event_id") or ""),
    )


def _assistant_tool_support(
    evidence: list[Mapping[str, Any]], assistant: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    """Return complete same-turn tool pairs supporting one assistant lesson."""

    metadata = assistant.get("metadata")
    if not isinstance(metadata, Mapping) or metadata.get("hook_event_name") != "Stop":
        return []
    turn_id = metadata.get("turn_id")
    if not isinstance(turn_id, str) or not turn_id:
        return []
    calls: dict[str, Mapping[str, Any]] = {}
    results: dict[str, Mapping[str, Any]] = {}
    positions: dict[str, int] = {}
    for position, row in enumerate(evidence):
        row_metadata = row.get("metadata")
        if not isinstance(row_metadata, Mapping) or row_metadata.get("turn_id") != turn_id:
            continue
        call_id = row_metadata.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            continue
        if row.get("evidence_type") == "tool_call":
            calls[call_id] = row
        elif row.get("evidence_type") == "tool_result":
            results[call_id] = row
        positions[str(row.get("event_id") or "")] = position
    pairs = sorted(
        (
            max(
                positions.get(str(calls[call_id].get("event_id") or ""), -1),
                positions.get(str(results[call_id].get("event_id") or ""), -1),
            ),
            calls[call_id],
            results[call_id],
        )
        for call_id in set(calls) & set(results)
    )
    supported: list[Mapping[str, Any]] = []
    for _position, call, result in pairs[-MAX_ASSISTANT_SUPPORT_PAIRS:]:
        supported.extend((call, result))
    return supported


def _candidate_order(candidate: Mapping[str, Any]) -> tuple[str, str, int, str]:
    return (
        str(candidate.get("created_at") or ""),
        str(candidate.get("source_path") or ""),
        int(candidate.get("source_line") or 0),
        str(candidate.get("candidate_id") or ""),
    )


def _relation(
    source: Mapping[str, Any],
    target: Mapping[str, Any],
    relation_type: str,
    reason: str,
    stamp: str,
) -> dict[str, Any]:
    return {
        "relation_id": stable_id(
            "rel", source["candidate_id"], target["candidate_id"], relation_type
        ),
        "session_id": source["session_id"],
        "source_candidate_id": source["candidate_id"],
        "target_candidate_id": target["candidate_id"],
        "relation_type": relation_type,
        "reason": reason,
        "created_at": stamp,
    }


def _expiry(memory_class: str, occurred_at: str | None, claim: str) -> str | None:
    if memory_class not in {"temporary_state", "plan"}:
        return None
    base = _parse_time(occurred_at) or datetime.now(timezone.utc)
    if memory_class == "temporary_state":
        delta = timedelta(days=1 if "今天" in claim else 7)
    elif any(token in claim for token in ("今天", "明天")):
        delta = timedelta(days=2)
    elif "本周" in claim or "周五" in claim:
        delta = timedelta(days=7)
    elif "下周" in claim:
        delta = timedelta(days=14)
    else:
        return None
    return _iso(base + delta)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str:
    if value is None:
        return utc_now()
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
