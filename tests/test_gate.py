"""Tests for soc2_refimpl.gate (TSC CC7.4)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from soc2_refimpl.gate import ComplianceGate
from soc2_refimpl.models import GateDecision


class TestComplianceGateInit:
    def test_initialises_without_error(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        assert gate is not None

    def test_default_gate_id(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        assert gate._gate_id == "loan-summary-confidence"  # type: ignore[attr-defined]

    def test_custom_gate_id(self, base_config: object) -> None:
        gate = ComplianceGate(base_config, gate_id="my-custom-gate")  # type: ignore[arg-type]
        assert gate._gate_id == "my-custom-gate"  # type: ignore[attr-defined]


class TestComplianceGateEvaluate:
    def _mock_pass_verdict(self) -> MagicMock:
        from spanforge.sdk.gate import GateVerdict

        result = MagicMock()
        result.verdict = GateVerdict.PASS
        return result

    def _mock_block_verdict(self) -> MagicMock:
        from spanforge.sdk.gate import GateVerdict

        result = MagicMock()
        result.verdict = GateVerdict.FAIL
        return result

    def test_evaluate_returns_gate_decision(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-001", "Approve the loan.", confidence=0.91)
        assert isinstance(decision, GateDecision)

    def test_evaluate_pass_sets_passed_true(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-001", "Approve.", confidence=0.91)
        assert decision.passed is True

    def test_evaluate_pass_not_routed_to_human(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-001", "Approve.", confidence=0.91)
        assert decision.routed_to_human is False

    def test_evaluate_block_sets_passed_false(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_block_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-002", "Unsure.", confidence=0.50)
        assert decision.passed is False

    def test_evaluate_block_sets_routed_to_human(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_block_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-002", "Unsure.", confidence=0.50)
        assert decision.routed_to_human is True

    def test_evaluate_sets_invocation_id(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("unique-inv-99", "Approve.", confidence=0.91)
        assert decision.invocation_id == "unique-inv-99"

    def test_evaluate_sets_confidence(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-003", "Approve.", confidence=0.93)
        assert decision.confidence == pytest.approx(0.93)

    def test_evaluate_sets_decided_at(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-004", "Approve.", confidence=0.91)
        assert decision.decided_at != ""

    def test_client_exception_falls_back_to_threshold(
        self, base_config: object
    ) -> None:
        """When SFGateClient raises, fall back to threshold comparison."""
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", side_effect=Exception("network error")):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-005", "Approve.", confidence=0.91)
        # 0.91 >= 0.82 threshold → pass
        assert decision.passed is True

    def test_client_exception_fallback_block(
        self, high_confidence_config: object
    ) -> None:
        """Fallback: confidence 0.50 below threshold 0.99 → block."""
        gate = ComplianceGate(high_confidence_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", side_effect=Exception("timeout")):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-006", "Unsure.", confidence=0.50)
        assert decision.passed is False

    def test_escalation_queue_set_on_block(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_block_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-007", "Unsure.", confidence=0.50)
        assert decision.escalation_queue != ""

    def test_escalation_queue_empty_on_pass(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-008", "Approve.", confidence=0.91)
        assert decision.escalation_queue == ""

    def test_threshold_stored_in_decision(self, base_config: object) -> None:
        gate = ComplianceGate(base_config)  # type: ignore[arg-type]
        with patch.object(gate._client, "evaluate", return_value=self._mock_pass_verdict()):  # type: ignore[attr-defined]
            decision = gate.evaluate("inv-009", "Approve.", confidence=0.91)
        assert decision.threshold == pytest.approx(0.82)
