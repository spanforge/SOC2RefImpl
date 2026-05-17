"""Tests for soc2_refimpl.exceptions."""

from __future__ import annotations

import pytest

from soc2_refimpl.exceptions import (
    AuditChainError,
    ComplianceError,
    DriftAlertError,
    GateBlockedError,
    PIIBlockedError,
    SecretDetectedError,
)


class TestComplianceError:
    def test_is_exception(self) -> None:
        exc = ComplianceError("test message")
        assert isinstance(exc, Exception)

    def test_tsc_criterion_stored(self) -> None:
        exc = ComplianceError("test", tsc_criterion="CC6.1")
        assert exc.tsc_criterion == "CC6.1"

    def test_message_stored(self) -> None:
        exc = ComplianceError("something went wrong")
        assert "something went wrong" in str(exc)


class TestPIIBlockedError:
    def test_inherits_compliance_error(self) -> None:
        exc = PIIBlockedError(["SSN", "CREDIT_CARD"])
        assert isinstance(exc, ComplianceError)

    def test_tsc_criterion_is_cc66(self) -> None:
        exc = PIIBlockedError(["SSN"])
        assert exc.tsc_criterion == "CC6.6"

    def test_entity_types_stored(self) -> None:
        exc = PIIBlockedError(["SSN", "ACCOUNT_NUMBER"])
        assert exc.entity_types == ["SSN", "ACCOUNT_NUMBER"]

    def test_entity_types_in_str(self) -> None:
        exc = PIIBlockedError(["SSN"])
        assert "SSN" in str(exc)

    def test_empty_entity_types(self) -> None:
        exc = PIIBlockedError([])
        assert exc.entity_types == []


class TestSecretDetectedError:
    def test_inherits_compliance_error(self) -> None:
        exc = SecretDetectedError(["API_KEY"])
        assert isinstance(exc, ComplianceError)

    def test_tsc_criterion_is_cc68(self) -> None:
        exc = SecretDetectedError(["API_KEY"])
        assert exc.tsc_criterion == "CC6.8"

    def test_secret_types_stored(self) -> None:
        exc = SecretDetectedError(["API_KEY", "BEARER_TOKEN"])
        assert exc.secret_types == ["API_KEY", "BEARER_TOKEN"]


class TestDriftAlertError:
    def test_inherits_compliance_error(self) -> None:
        exc = DriftAlertError("response_length", 4.5)
        assert isinstance(exc, ComplianceError)

    def test_tsc_criterion_is_cc72(self) -> None:
        exc = DriftAlertError("latency_ms", 3.1)
        assert exc.tsc_criterion == "CC7.2"

    def test_metric_name_stored(self) -> None:
        exc = DriftAlertError("confidence_score", 5.0)
        assert exc.metric_name == "confidence_score"

    def test_z_score_stored(self) -> None:
        exc = DriftAlertError("latency_ms", 3.8)
        assert exc.z_score == pytest.approx(3.8)


class TestGateBlockedError:
    def test_inherits_compliance_error(self) -> None:
        exc = GateBlockedError(confidence=0.50, threshold=0.82)
        assert isinstance(exc, ComplianceError)

    def test_tsc_criterion_is_cc74(self) -> None:
        exc = GateBlockedError(0.50, 0.82)
        assert exc.tsc_criterion == "CC7.4"

    def test_confidence_stored(self) -> None:
        exc = GateBlockedError(0.50, 0.82)
        assert exc.confidence == pytest.approx(0.50)

    def test_threshold_stored(self) -> None:
        exc = GateBlockedError(0.50, 0.82)
        assert exc.threshold == pytest.approx(0.82)


class TestAuditChainError:
    def test_inherits_compliance_error(self) -> None:
        exc = AuditChainError(first_tampered="event-1", gaps=["gap-1"])
        assert isinstance(exc, ComplianceError)

    def test_tsc_criterion_is_cc92(self) -> None:
        exc = AuditChainError(first_tampered="event-1", gaps=[])
        assert exc.tsc_criterion == "CC9.2"

    def test_first_tampered_stored(self) -> None:
        exc = AuditChainError(first_tampered="event-5", gaps=[])
        assert exc.first_tampered == "event-5"

    def test_gaps_stored(self) -> None:
        exc = AuditChainError(first_tampered=None, gaps=["gap-a", "gap-b"])
        assert exc.gaps == ["gap-a", "gap-b"]

    def test_first_tampered_can_be_none(self) -> None:
        exc = AuditChainError(first_tampered=None, gaps=[])
        assert exc.first_tampered is None
