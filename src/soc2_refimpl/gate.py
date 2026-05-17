"""
soc2_refimpl.gate — human-in-the-loop compliance gate (TSC CC7.4).

Evaluates LLM output against a configurable confidence threshold and routes
low-confidence responses to a human review queue.  Every evaluation decision
is recorded in the audit chain as an escalation-journal entry.

Evidence produced: one :class:`~soc2_refimpl.models.GateDecision` per
invocation, included in the CC7.4 section of the audit bundle.
"""

from __future__ import annotations

import logging

from spanforge.sdk.gate import (  # type: ignore[import-untyped, attr-defined, no-untyped-def]
    GateVerdict,
    SFClientConfig,
    SFGateClient,
)

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.models import GateDecision, utc_now_iso

log = logging.getLogger(__name__)

# Default gate identifier — must match the gate registered in SpanForge project
_DEFAULT_GATE_ID = "loan-summary-confidence"


class ComplianceGate:
    """Evaluates model output against the confidence gate (CC7.4).

    Parameters
    ----------
    config:
        Pipeline configuration (provides confidence threshold, project ID, and
        escalation queue name).
    gate_id:
        Identifier of the gate definition in the SpanForge project.
    """

    def __init__(
        self,
        config: PipelineConfig,
        gate_id: str = _DEFAULT_GATE_ID,
    ) -> None:
        sf_cfg: SFClientConfig = config.to_sf_client_config()  # type: ignore[assignment]
        self._client = SFGateClient(sf_cfg)
        self._threshold = config.confidence_threshold
        self._escalation_queue = config.escalation_queue
        self._project_id = config.project_id
        self._gate_id = gate_id
        log.debug(
            "ComplianceGate initialised (gate=%s, threshold=%.2f, queue=%s)",
            gate_id,
            config.confidence_threshold,
            config.escalation_queue,
        )

    def evaluate(
        self,
        invocation_id: str,
        answer: str,
        confidence: float,
    ) -> GateDecision:
        """Evaluate *answer* against the confidence gate.

        Parameters
        ----------
        invocation_id:
            Unique ID of the current pipeline invocation.
        answer:
            LLM output text (after PII redaction and secret scanning).
        confidence:
            Confidence score in [0, 1] produced by the LLM or scoring model.

        Returns
        -------
        GateDecision
            Decision record indicating whether the response passed or was
            escalated to human review.
        """
        payload = {
            "answer": answer[:500],  # truncate for gate payload size limits
            "confidence": confidence,
            "threshold": self._threshold,
            "invocation_id": invocation_id,
        }

        try:
            gate_result = self._client.evaluate(
                self._gate_id,
                payload,
                project_id=self._project_id,
                pipeline_id=self._project_id,
            )
            verdict = gate_result.verdict if hasattr(gate_result, "verdict") else GateVerdict.PASS
            # Always enforce the confidence threshold as the hard floor.
            # In local fallback mode the gate backend returns PASS unconditionally;
            # this guard ensures the threshold is respected regardless (CC7.4).
            if verdict == GateVerdict.PASS and confidence < self._threshold:
                log.debug(
                    "Gate returned PASS but confidence %.3f < threshold %.3f "
                    "— overriding to FAIL (CC7.4)",
                    confidence,
                    self._threshold,
                )
                verdict = GateVerdict.FAIL
        except Exception:
            # In local fallback mode the gate client may not have a registered
            # gate definition; fall back to threshold-only evaluation.
            log.debug("Gate evaluate() unavailable; using threshold fallback (CC7.4)")
            verdict = (
                GateVerdict.PASS if confidence >= self._threshold else GateVerdict.FAIL
            )

        passed = verdict == GateVerdict.PASS
        routed = not passed

        if routed:
            log.warning(
                "Gate BLOCKED invocation %s (confidence=%.3f < %.3f) — routing to %s (CC7.4)",
                invocation_id,
                confidence,
                self._threshold,
                self._escalation_queue,
            )
        else:
            log.info(
                "Gate PASSED invocation %s (confidence=%.3f) (CC7.4)",
                invocation_id,
                confidence,
            )

        return GateDecision(
            invocation_id=invocation_id,
            confidence=confidence,
            threshold=self._threshold,
            passed=passed,
            routed_to_human=routed,
            escalation_queue=self._escalation_queue if routed else "",
            decided_at=utc_now_iso(),
            gate_id=self._gate_id,
        )
