"""
soc2_refimpl.exceptions — typed exception hierarchy for compliance violations.

Each exception maps to a specific TSC criterion so callers can handle them
selectively and so audit log entries carry precise violation codes.
"""

from __future__ import annotations


class ComplianceError(Exception):
    """Base class for all SOC 2 compliance-related errors."""

    tsc_criterion: str = "UNKNOWN"

    def __init__(self, message: str, *, tsc_criterion: str | None = None) -> None:
        super().__init__(message)
        if tsc_criterion is not None:
            self.tsc_criterion = tsc_criterion


class PIIBlockedError(ComplianceError):
    """Raised when critical PII cannot be redacted before passing to the LLM.

    TSC: CC6.6 — Restriction of access to sensitive data.
    """

    tsc_criterion = "CC6.6"

    def __init__(self, entity_types: list[str]) -> None:
        types_str = ", ".join(entity_types)
        super().__init__(
            f"Critical PII detected and cannot be redacted: {types_str}. "
            "Processing halted to protect sensitive data (CC6.6).",
        )
        self.entity_types = entity_types


class SecretDetectedError(ComplianceError):
    """Raised when a credential or secret is detected in the model output.

    TSC: CC6.8 — Prevention of unauthorized output.
    """

    tsc_criterion = "CC6.8"

    def __init__(self, secret_types: list[str]) -> None:
        types_str = ", ".join(secret_types)
        super().__init__(
            f"Secret(s) detected in model output: {types_str}. "
            "Output suppressed and alert raised (CC6.8).",
        )
        self.secret_types = secret_types


class DriftAlertError(ComplianceError):
    """Raised when a behavioural drift breach is detected for a metric.

    TSC: CC7.2 — System monitoring.
    """

    tsc_criterion = "CC7.2"

    def __init__(self, metric_name: str, z_score: float) -> None:
        super().__init__(
            f"Drift breach detected on '{metric_name}' (z-score={z_score:.2f}). "
            "Review output distribution and update baseline if expected (CC7.2).",
        )
        self.metric_name = metric_name
        self.z_score = z_score


class GateBlockedError(ComplianceError):
    """Raised when the compliance gate blocks an output due to low confidence.

    TSC: CC7.4 — Incident response / human-in-the-loop.
    """

    tsc_criterion = "CC7.4"

    def __init__(self, confidence: float, threshold: float) -> None:
        super().__init__(
            f"Gate blocked: confidence {confidence:.3f} < threshold {threshold:.3f}. "
            "Routed to human review queue (CC7.4).",
        )
        self.confidence = confidence
        self.threshold = threshold


class AuditChainError(ComplianceError):
    """Raised when the HMAC audit chain fails verification.

    TSC: CC9.2 — Risk monitoring / chain of custody.
    """

    tsc_criterion = "CC9.2"

    def __init__(self, first_tampered: str | None, gaps: list[str]) -> None:
        details = []
        if first_tampered:
            details.append(f"first tampered event_id={first_tampered}")
        if gaps:
            details.append(f"chain gaps at event_ids={gaps}")
        super().__init__(
            "Audit chain integrity check FAILED. "
            + ("; ".join(details) if details else "unknown tampering")
            + " (CC9.2).",
        )
        self.first_tampered = first_tampered
        self.gaps = gaps
