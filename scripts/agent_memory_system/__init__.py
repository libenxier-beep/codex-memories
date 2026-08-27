"""Single-user local Agent Memory runtime building blocks."""

from .capture import CaptureError, CaptureReceipt, TranscriptCapture
from .reliability import (
    DurableJob,
    HealthReport,
    LeaseConflict,
    PipelineReliability,
    RecoveryReceipt,
)
from .redaction import RedactionPolicy
from .store import (
    AgentMemoryStore,
    RetentionPolicy,
    RetentionPurgeError,
    RetentionQuotaExceeded,
)

__all__ = [
    "AgentMemoryStore",
    "CaptureError",
    "CaptureReceipt",
    "DurableJob",
    "HealthReport",
    "LeaseConflict",
    "PipelineReliability",
    "RecoveryReceipt",
    "RedactionPolicy",
    "RetentionPolicy",
    "RetentionPurgeError",
    "RetentionQuotaExceeded",
    "TranscriptCapture",
]

try:
    from .candidates import CandidateBatchReceipt, CandidateFormer
except ImportError:
    # Candidate formation is an independently testable optional stage while the
    # evidence and reliability seams remain importable during staged upgrades.
    pass
else:
    __all__.extend(["CandidateBatchReceipt", "CandidateFormer"])
