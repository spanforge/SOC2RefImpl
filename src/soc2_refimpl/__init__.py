"""
soc2_refimpl — SpanForge SOC 2 Type II Reference Implementation.

This package provides a complete, production-grade instrumented LLM pipeline
that satisfies SOC 2 Trust Service Criteria CC6.1, CC6.6, CC6.8, CC7.2,
CC7.4, CC9.2, and A1.2 using SpanForge 2.0.x primitives.

Typical usage::

    from soc2_refimpl import LoanSummaryPipeline, PipelineConfig

    config = PipelineConfig.from_env()
    pipeline = LoanSummaryPipeline(config)
    result = pipeline.run(application_id="APP-001", documents=["doc text..."])
    print(result.answer)
"""

from __future__ import annotations

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.exceptions import (
    AuditChainError,
    ComplianceError,
    DriftAlertError,
    GateBlockedError,
    PIIBlockedError,
    SecretDetectedError,
)
from soc2_refimpl.models import (
    GateDecision,
    InvocationRecord,
    PipelineResult,
    RedactionRecord,
    SecretScanRecord,
)
from soc2_refimpl.pipeline import LoanSummaryPipeline

__all__ = [
    "AuditChainError",
    "ComplianceError",
    "DriftAlertError",
    "GateBlockedError",
    "GateDecision",
    "InvocationRecord",
    "LoanSummaryPipeline",
    "PIIBlockedError",
    "PipelineConfig",
    "PipelineResult",
    "RedactionRecord",
    "SecretDetectedError",
    "SecretScanRecord",
]

__version__ = "1.0.0"
