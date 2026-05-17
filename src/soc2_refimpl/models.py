"""
soc2_refimpl.models — shared data models for the compliance pipeline.

All models are plain Python dataclasses so they serialise to/from dict
without an extra dependency, yet remain type-safe.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RedactionRecord:
    """Evidence record for CC6.6 — PII redaction.

    One record is emitted per document processed by the pipeline.
    The list is included verbatim in the audit bundle.
    """

    document_index: int
    entity_types_detected: list[str]
    entity_count: int
    redacted: bool
    redacted_at: str  # ISO-8601 UTC
    pre_hash: str  # SHA-256 of original text for fingerprinting

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_index": self.document_index,
            "entity_types_detected": self.entity_types_detected,
            "entity_count": self.entity_count,
            "redacted": self.redacted,
            "redacted_at": self.redacted_at,
            "pre_hash": self.pre_hash,
        }


@dataclass
class SecretScanRecord:
    """Evidence record for CC6.8 — secret scan result.

    One record is emitted per LLM response.
    """

    invocation_id: str
    detected: bool
    secret_types: list[str]
    auto_blocked: bool
    scanned_at: str  # ISO-8601 UTC

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "detected": self.detected,
            "secret_types": self.secret_types,
            "auto_blocked": self.auto_blocked,
            "scanned_at": self.scanned_at,
        }


@dataclass
class GateDecision:
    """Evidence record for CC7.4 — gate evaluation decision.

    Captures confidence score, routing decision, and escalation metadata.
    """

    invocation_id: str
    confidence: float
    threshold: float
    passed: bool
    routed_to_human: bool
    escalation_queue: str
    decided_at: str  # ISO-8601 UTC
    gate_id: str = "loan-summary-confidence"

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "confidence": self.confidence,
            "threshold": self.threshold,
            "passed": self.passed,
            "routed_to_human": self.routed_to_human,
            "escalation_queue": self.escalation_queue,
            "decided_at": self.decided_at,
            "gate_id": self.gate_id,
        }


@dataclass
class InvocationRecord:
    """Top-level audit record for CC6.1 — logical access / trace.

    One record is emitted per pipeline invocation.  It aggregates references
    to all child evidence records so the audit bundle can cross-link them.
    """

    invocation_id: str
    application_id: str
    model: str
    operation: str
    status: str  # "ok" | "error" | "escalated"
    duration_ms: float
    started_at: str  # ISO-8601 UTC
    finished_at: str  # ISO-8601 UTC
    tsc_criteria: list[str]
    pii_records: list[RedactionRecord] = field(default_factory=list)
    secret_record: SecretScanRecord | None = None
    gate_decision: GateDecision | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "invocation_id": self.invocation_id,
            "application_id": self.application_id,
            "model": self.model,
            "operation": self.operation,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "tsc_criteria": self.tsc_criteria,
            "pii_records": [r.to_dict() for r in self.pii_records],
        }
        if self.secret_record is not None:
            d["secret_record"] = self.secret_record.to_dict()
        if self.gate_decision is not None:
            d["gate_decision"] = self.gate_decision.to_dict()
        if self.error is not None:
            d["error"] = self.error
        return d


@dataclass
class PipelineResult:
    """Final output returned to the caller by :class:`~soc2_refimpl.pipeline.LoanSummaryPipeline`.

    ``answer`` contains the (possibly redacted) LLM output.
    ``invocation`` is the full audit record for this run.
    ``routed_to_human`` indicates whether the gate escalated this response.
    """

    answer: str
    invocation: InvocationRecord
    routed_to_human: bool
    drift_breaches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer": self.answer,
            "invocation": self.invocation.to_dict(),
            "routed_to_human": self.routed_to_human,
            "drift_breaches": self.drift_breaches,
        }


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.datetime.now(tz=datetime.UTC).isoformat()
