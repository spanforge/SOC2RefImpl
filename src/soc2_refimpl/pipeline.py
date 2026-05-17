"""
soc2_refimpl.pipeline — LoanSummaryPipeline — main orchestrator (TSC CC6.1).

This module wires all compliance primitives together into a single cohesive
pipeline that mirrors the ``loan_summary.py`` reference from the SpanForge
SOC 2 document.

Architecture (per invocation)::

    1. @trace  — emit signed span (CC6.1)
    2. sf_pii  — scan + redact documents (CC6.6)
    3. LLM     — generate summary (via LLMBackend protocol)
    4. sf_secrets — scan output for credentials (CC6.8)
    5. sf_drift — record metrics, detect drift (CC7.2)
    6. sf_gate  — confidence gate + HITL routing (CC7.4)
    7. audit    — append all records to HMAC chain (CC9.2)
    8. observe  — emit OTel availability span (A1.2)

The ``LLMBackend`` protocol allows any LLM provider to be plugged in without
coupling this module to a specific SDK.  A ``MockLLMBackend`` is provided for
testing and demonstration.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from soc2_refimpl.audit_chain import AuditChain
from soc2_refimpl.availability import AvailabilityMonitor
from soc2_refimpl.compliance import ComplianceExporter
from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.drift_monitor import DriftMonitor, DriftObservation
from soc2_refimpl.exceptions import (
    AuditChainError,
    PIIBlockedError,
    SecretDetectedError,
)
from soc2_refimpl.gate import ComplianceGate
from soc2_refimpl.models import InvocationRecord, PipelineResult, utc_now_iso
from soc2_refimpl.pii_handler import PIIHandler
from soc2_refimpl.secrets_scanner import SecretsScanner

log = logging.getLogger(__name__)


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for pluggable LLM backends.

    Any object implementing ``generate(prompt)`` can be used as the
    language model in :class:`LoanSummaryPipeline`.
    """

    def generate(self, prompt: str) -> tuple[str, float]:
        """Generate a response and return ``(answer, confidence)``."""
        ...


@dataclass
class MockLLMBackend:
    """Deterministic mock LLM for testing and local demonstration.

    Parameters
    ----------
    response:
        Fixed response text returned for every prompt.
    confidence:
        Fixed confidence score in [0, 1].
    latency_ms:
        Simulated generation latency in milliseconds.
    """

    response: str = (
        "Based on the provided financial documents, the applicant demonstrates "
        "a debt-to-income ratio within acceptable parameters for the requested "
        "loan amount. Underwriter review recommended for final approval."
    )
    confidence: float = 0.91
    latency_ms: float = 850.0

    def generate(self, prompt: str) -> tuple[str, float]:
        """Return the fixed response and confidence."""
        if self.latency_ms > 0:
            time.sleep(self.latency_ms / 1000.0)
        return self.response, self.confidence


class LoanSummaryPipeline:
    """SOC 2-compliant loan summary generation pipeline.

    This pipeline instruments every stage with SpanForge compliance primitives
    and produces an auditable evidence trail for TSC CC6.1, CC6.6, CC6.8,
    CC7.2, CC7.4, CC9.2, and A1.2.

    Parameters
    ----------
    config:
        Pipeline configuration (from environment or explicit values).
    llm:
        Pluggable LLM backend.  Defaults to :class:`MockLLMBackend`.

    Example
    -------
    ::

        from soc2_refimpl import LoanSummaryPipeline, PipelineConfig

        cfg = PipelineConfig.from_env()
        pipeline = LoanSummaryPipeline(cfg)
        result = pipeline.run("APP-001", ["Applicant income: $120,000"])
        print(result.answer)
    """

    def __init__(
        self,
        config: PipelineConfig,
        llm: LLMBackend | None = None,
    ) -> None:
        self._config = config
        self._llm: LLMBackend = llm or MockLLMBackend()

        # Initialise compliance primitives
        self._pii = PIIHandler(config)
        self._secrets = SecretsScanner(config)
        self._drift = DriftMonitor(config)
        self._gate = ComplianceGate(config)
        self._audit = AuditChain(config)
        self._availability = AvailabilityMonitor(config)
        self._compliance = ComplianceExporter(config, self._audit, self._availability)

        log.info("LoanSummaryPipeline initialised (project=%s)", config.project_id)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(
        self,
        application_id: str,
        documents: list[str],
        *,
        confidence_override: float | None = None,
    ) -> PipelineResult:
        """Generate a compliant loan summary for *application_id*.

        Parameters
        ----------
        application_id:
            Identifier of the loan application (used in audit records).
        documents:
            Raw document strings (loan application, financial statements, etc.).
            PII will be detected and redacted before these are passed to the LLM.
        confidence_override:
            For testing: override the confidence score returned by the LLM.

        Returns
        -------
        PipelineResult
            The (possibly redacted) answer and full audit record.

        Raises
        ------
        PIIBlockedError
            If critical PII (SSN, account numbers) is found that cannot be
            safely redacted (CC6.6).
        SecretDetectedError
            If ``block_on_detection=True`` and secrets appear in LLM output (CC6.8).
        GateBlockedError
            If the compliance gate blocks output (CC7.4). Note: by default the
            gate routes to human review rather than raising; set
            ``config.raise_on_gate_block=True`` to raise instead.
        """
        invocation_id = str(uuid.uuid4())
        started_at = utc_now_iso()
        t_start = time.monotonic()
        status = "ok"
        error_msg: str | None = None
        drift_breaches: list[str] = []

        log.info(
            "Pipeline START invocation_id=%s application_id=%s (CC6.1)",
            invocation_id,
            application_id,
        )

        try:
            # ── Step 1: PII detection and redaction (CC6.6) ──────────────
            clean_docs, pii_records = self._pii.process_documents(documents)

            # ── Step 2: Build prompt and invoke LLM ──────────────────────
            prompt = self._build_prompt(application_id, clean_docs)
            llm_answer, llm_confidence = self._llm.generate(prompt)
            confidence = confidence_override if confidence_override is not None else llm_confidence

            # ── Step 3: Secret scan on LLM output (CC6.8) ────────────────
            clean_answer, secret_record = self._secrets.scan(invocation_id, llm_answer)

            # ── Step 4: Drift detection (CC7.2) ──────────────────────────
            duration_ms = (time.monotonic() - t_start) * 1000
            obs = DriftObservation(
                response_length=float(len(clean_answer)),
                confidence_score=confidence,
                latency_ms=duration_ms,
                invocation_id=invocation_id,
            )
            drift_breaches = self._drift.observe(obs)
            for breach in drift_breaches:
                alert = self._drift.make_alert_payload(breach)
                self._audit.record_drift(alert, invocation_id)
                self._compliance.add_drift_alert(alert)

            # ── Step 5: Compliance gate (CC7.4) ──────────────────────────
            gate_decision = self._gate.evaluate(invocation_id, clean_answer, confidence)

            # ── Step 6: Audit trail (CC9.2) ──────────────────────────────
            self._audit.record_pii(pii_records, invocation_id)
            self._audit.record_secrets(secret_record)
            self._audit.record_gate(gate_decision)
            self._compliance.add_pii_records(pii_records)
            self._compliance.add_secret_record(secret_record)
            self._compliance.add_gate_decision(gate_decision)

            if gate_decision.routed_to_human:
                status = "escalated"

        except (PIIBlockedError, SecretDetectedError) as exc:
            status = "error"
            error_msg = str(exc)
            duration_ms = (time.monotonic() - t_start) * 1000
            clean_answer = ""
            pii_records = []
            secret_record = None  # type: ignore[assignment]
            gate_decision = None  # type: ignore[assignment]
            log.error("Pipeline BLOCKED [%s]: %s", invocation_id, exc)
            raise

        except Exception as exc:
            status = "error"
            error_msg = str(exc)
            duration_ms = (time.monotonic() - t_start) * 1000
            clean_answer = ""
            pii_records = []
            secret_record = None  # type: ignore[assignment]
            gate_decision = None  # type: ignore[assignment]
            log.error("Pipeline ERROR [%s]: %s", invocation_id, exc)
            raise

        finally:
            finished_at = utc_now_iso()
            duration_ms = (time.monotonic() - t_start) * 1000

            invocation_record = InvocationRecord(
                invocation_id=invocation_id,
                application_id=application_id,
                model=self._config.model,
                operation="loan_summary_generation",
                status=status,
                duration_ms=duration_ms,
                started_at=started_at,
                finished_at=finished_at,
                tsc_criteria=self._config.tsc_criteria,
                pii_records=pii_records if pii_records else [],
                secret_record=secret_record if "secret_record" in dir() else None,
                gate_decision=gate_decision if "gate_decision" in dir() else None,
                error=error_msg,
            )

            self._audit.record_invocation(invocation_record)
            self._compliance.add_invocation(invocation_record)

            # ── Step 7: Availability metrics (A1.2) ──────────────────────
            self._availability.record_invocation(
                invocation_id=invocation_id,
                duration_ms=duration_ms,
                success=(status != "error"),
            )

            log.info(
                "Pipeline END invocation_id=%s status=%s duration=%.1fms (CC6.1, A1.2)",
                invocation_id,
                status,
                duration_ms,
            )

        return PipelineResult(
            answer=clean_answer,
            invocation=invocation_record,
            routed_to_human=gate_decision.routed_to_human if gate_decision else False,
            drift_breaches=drift_breaches,
        )

    def export_evidence_bundle(self) -> dict[str, Any]:
        """Export all accumulated evidence records to the local audit directory.

        Returns
        -------
        dict[str, Any]
            Mapping of artifact names to absolute paths.

        Note
        ----
        Call :meth:`~soc2_refimpl.audit_chain.AuditChain.verify` before
        exporting to confirm the audit chain is intact (CC9.2).
        """
        self._audit.verify()
        paths = self._compliance.export_local()
        return {name: str(path) for name, path in paths.items()}

    def verify_audit_chain(self) -> bool:
        """Verify HMAC audit chain integrity.

        Returns
        -------
        bool
            ``True`` if the chain is intact.

        Raises
        ------
        AuditChainError
            If any tampering or gaps are detected (CC9.2).
        """
        try:
            result = self._audit.verify()
            return result.valid
        except AuditChainError:
            return False

    def close(self) -> None:
        """Release all resources held by the pipeline."""
        self._audit.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_prompt(self, application_id: str, clean_docs: list[str]) -> str:
        """Build the LLM prompt from redacted documents."""
        joined = "\n\n".join(clean_docs)
        return (
            f"Application ID: {application_id}\n\n"
            "You are a loan underwriting assistant. Summarise the following "
            "financial documents and provide a risk assessment recommendation.\n\n"
            f"Documents:\n{joined}"
        )
