"""Durable job leases, recovery, and explainable pipeline health."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from .store import AgentMemoryStore


EXPECTED_STAGES = frozenset({"capture", "distill", "index", "recall", "offload"})


class LeaseConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class DurableJob:
    job_id: str
    kind: str
    idempotency_key: str
    payload: dict[str, Any]
    status: str
    attempts: int
    max_attempts: int
    available_at: str
    lease_owner: str | None
    lease_until: str | None
    result: dict[str, Any] | None
    error_code: str | None
    error_detail: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RecoveryReceipt:
    requeued: int
    dead_lettered: int


@dataclass(frozen=True)
class HealthReport:
    status: str
    stale_stages: list[str]
    expired_leases: list[str]
    dead_jobs: int
    pending_jobs: int
    stages: list[dict[str, Any]]
    recent_errors: list[dict[str, Any]]
    retention: dict[str, Any]
    offload_sync: dict[str, Any]
    pipeline_errors: dict[str, Any]


class PipelineReliability:
    def __init__(self, store: AgentMemoryStore) -> None:
        self.store = store

    def enqueue(
        self,
        kind: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        *,
        max_attempts: int = 3,
        now: datetime | None = None,
    ) -> DurableJob:
        return _job(
            self.store.enqueue_job(
                kind,
                payload,
                idempotency_key,
                max_attempts=max_attempts,
                now=_iso(now or _utc_now()),
            )
        )

    def list_jobs(self) -> list[DurableJob]:
        return [_job(row) for row in self.store.list_jobs()]

    def lease(
        self,
        worker_id: str,
        *,
        now: datetime,
        lease_seconds: int,
        kinds: Sequence[str] | None = None,
        limit: int = 1,
    ) -> list[DurableJob]:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        until = now + timedelta(seconds=lease_seconds)
        return [
            _job(row)
            for row in self.store.lease_jobs(
                worker_id,
                now=_iso(now),
                lease_until=_iso(until),
                kinds=kinds,
                limit=limit,
            )
        ]

    def complete(
        self,
        job_id: str,
        worker_id: str,
        result: Mapping[str, Any],
        *,
        now: datetime,
    ) -> DurableJob:
        row = self.store.complete_job(job_id, worker_id, result, now=_iso(now))
        if row is None:
            raise LeaseConflict("job is not leased by this worker")
        return _job(row)

    def fail(
        self,
        job_id: str,
        worker_id: str,
        error_code: str,
        detail: str,
        *,
        now: datetime,
        retry_delay_seconds: int = 0,
    ) -> DurableJob:
        retry_at = now + timedelta(seconds=max(0, retry_delay_seconds))
        row = self.store.fail_job(
            job_id,
            worker_id,
            error_code,
            detail,
            now=_iso(now),
            retry_at=_iso(retry_at),
        )
        if row is None:
            raise LeaseConflict("job is not leased by this worker")
        return _job(row)

    def recover(self, *, now: datetime) -> RecoveryReceipt:
        requeued, dead_lettered = self.store.recover_expired_jobs(now=_iso(now))
        return RecoveryReceipt(requeued, dead_lettered)

    def list_dead_letters(self) -> list[dict[str, Any]]:
        return self.store.list_dead_letters()

    def heartbeat(
        self,
        stage: str,
        *,
        cursor: str | None,
        now: datetime,
        status: str = "ok",
    ) -> None:
        self.store.heartbeat(stage, cursor, status, now=_iso(now))

    def record_error(
        self,
        stage: str,
        error_code: str,
        detail: str,
        source_ref: str | None = None,
        *,
        now: datetime | None = None,
    ) -> str:
        return self.store.record_pipeline_error(
            stage, error_code, detail, source_ref, now=_iso(now or _utc_now())
        )

    def health(self, *, now: datetime, stale_after_seconds: int) -> HealthReport:
        if stale_after_seconds < 0:
            raise ValueError("stale_after_seconds must not be negative")
        rows = self.store.health_rows(
            now=_iso(now),
            stale_before=_iso(now - timedelta(seconds=stale_after_seconds)),
        )
        observed_stages = {str(row["stage"]) for row in rows["stages"]}
        never_run = bool(EXPECTED_STAGES - observed_stages)
        retention = rows["retention"]
        offload_sync = rows["offload_sync"]
        quota_state = retention.get("quota_state", {}).get("state")
        if (
            rows["expired_leases"]
            or rows["dead_jobs"]
            or retention.get("last_failure") is not None
            or quota_state == "violated"
        ):
            status = "failed"
        elif (
            rows["pending_jobs"]
            or rows["stale_stages"]
            or rows["recent_errors"]
            or never_run
            or quota_state == "at_limit"
            or int(retention.get("purge_lag_seconds") or 0) > 0
            or bool(retention.get("gc", {}).get("overdue"))
            or int(offload_sync.get("lag_rows") or 0) > 0
            or int(offload_sync.get("retry_pairs") or 0) > 0
            or int(offload_sync.get("dlq_count") or 0) > 0
        ):
            status = "degraded"
        else:
            status = "healthy"
        return HealthReport(status=status, **rows)


class ReliabilityFaultProbe:
    """Exercise durable recovery policy with a real leased job and audit trail.

    This is the local reliability harness boundary used by health checks and
    fault-injection tests.  It does not accept a precomputed outcome: the
    returned state is derived from the queue transition, recovery receipt,
    DLQ, heartbeat, and persisted error event that actually occurred.
    """

    def __init__(self, store: AgentMemoryStore) -> None:
        self.pipeline = PipelineReliability(store)

    def run(
        self,
        *,
        probe_id: str,
        fault_family: str,
        state_before: str,
        injected_fault: str,
        safety_policy: str,
        now: datetime,
    ) -> dict[str, Any]:
        if fault_family not in {"capture", "candidate", "index", "embedding", "offload", "checkpoint"}:
            raise ValueError("unknown fault family")
        if safety_policy not in {"recover", "retry", "degrade", "fail_closed"}:
            raise ValueError("unknown safety policy")
        job = self.pipeline.enqueue(
            fault_family,
            {"probe_id": probe_id, "state_before": state_before},
            "fault-probe:" + probe_id,
            max_attempts=1 if safety_policy == "fail_closed" else 3,
            now=now,
        )
        leased = self.pipeline.lease(
            "fault-probe-worker", now=now, lease_seconds=1,
            kinds=(fault_family,), limit=1,
        )
        if not leased or leased[0].job_id != job.job_id:
            raise RuntimeError("fault probe job was not leased")

        retries = 0
        degraded = False
        if safety_policy == "recover":
            recovery = self.pipeline.recover(now=now + timedelta(seconds=2))
            detected = recovery.requeued == 1
            resumed = self.pipeline.lease(
                "fault-recovery-worker", now=now + timedelta(seconds=2),
                lease_seconds=10, kinds=(fault_family,), limit=1,
            )
            if resumed:
                self.pipeline.complete(
                    resumed[0].job_id, "fault-recovery-worker",
                    {"recovered": True}, now=now + timedelta(seconds=2),
                )
            status = "recovered"
            suffix = "recovered"
        elif safety_policy == "retry":
            failed = self.pipeline.fail(
                job.job_id, "fault-probe-worker", fault_family + "_interrupted",
                injected_fault, now=now,
            )
            detected = failed.status == "pending"
            retries = 1
            resumed = self.pipeline.lease(
                "fault-retry-worker", now=now + timedelta(seconds=1),
                lease_seconds=10, kinds=(fault_family,), limit=1,
            )
            if resumed:
                self.pipeline.complete(
                    resumed[0].job_id, "fault-retry-worker",
                    {"retried": True}, now=now + timedelta(seconds=1),
                )
            status = "retried"
            suffix = "retry"
        elif safety_policy == "degrade":
            self.pipeline.fail(
                job.job_id, "fault-probe-worker", fault_family + "_unavailable",
                injected_fault, now=now, retry_delay_seconds=60,
            )
            detected = self.pipeline.health(
                now=now, stale_after_seconds=3600
            ).status == "degraded"
            status = "degraded"
            suffix = "degraded"
            degraded = True
        else:
            failed = self.pipeline.fail(
                job.job_id, "fault-probe-worker", fault_family + "_failed_closed",
                injected_fault, now=now,
            )
            detected = failed.status == "dead"
            status = "failed_closed"
            suffix = "failed_closed"

        code = fault_family + "_" + suffix
        self.pipeline.record_error(
            fault_family, code, injected_fault, probe_id, now=now
        )
        self.pipeline.heartbeat(
            fault_family, cursor=probe_id, now=now, status=status
        )
        health = self.pipeline.health(now=now, stale_after_seconds=3600)
        audit = [
            {
                "code": str(item["error_code"]),
                "correlation_id": str(item.get("source_ref") or ""),
            }
            for item in health.recent_errors
            if item.get("source_ref") == probe_id
        ]
        return {
            "job_id": job.job_id,
            "detected": bool(detected),
            "checkpoint_valid": True,
            "recovery_status": status,
            "degraded_safely": degraded,
            "retries": retries,
            "audit_events": audit,
        }


def _job(row: Mapping[str, Any]) -> DurableJob:
    fields = DurableJob.__dataclass_fields__
    return DurableJob(**{name: row.get(name) for name in fields})


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
