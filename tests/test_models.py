"""Tests for soc2_refimpl.models."""

from __future__ import annotations

from soc2_refimpl.models import (
    GateDecision,
    InvocationRecord,
    PipelineResult,
    RedactionRecord,
    SecretScanRecord,
    utc_now_iso,
)


class TestUtcNowIso:
    def test_returns_string(self) -> None:
        result = utc_now_iso()
        assert isinstance(result, str)

    def test_contains_timezone_marker(self) -> None:
        result = utc_now_iso()
        # ISO-8601 UTC timestamps end with +00:00
        assert "+00:00" in result or result.endswith("Z")

    def test_unique_on_each_call(self) -> None:
        import time
        t1 = utc_now_iso()
        time.sleep(0.001)
        t2 = utc_now_iso()
        # At millisecond precision they should differ
        assert t1 <= t2


class TestRedactionRecord:
    def test_to_dict_contains_required_keys(self) -> None:
        record = RedactionRecord(
            document_index=0,
            entity_types_detected=["EMAIL_ADDRESS"],
            entity_count=1,
            redacted=True,
            redacted_at="2026-01-01T00:00:00+00:00",
            pre_hash="abc123",
        )
        d = record.to_dict()
        assert d["document_index"] == 0
        assert d["entity_types_detected"] == ["EMAIL_ADDRESS"]
        assert d["entity_count"] == 1
        assert d["redacted"] is True
        assert d["redacted_at"] == "2026-01-01T00:00:00+00:00"
        assert d["pre_hash"] == "abc123"

    def test_no_entities_is_valid(self) -> None:
        record = RedactionRecord(
            document_index=1,
            entity_types_detected=[],
            entity_count=0,
            redacted=False,
            redacted_at="2026-01-01T00:00:00+00:00",
            pre_hash="def456",
        )
        d = record.to_dict()
        assert d["entity_count"] == 0
        assert d["redacted"] is False


class TestSecretScanRecord:
    def test_to_dict_no_detection(self) -> None:
        record = SecretScanRecord(
            invocation_id="inv-001",
            detected=False,
            secret_types=[],
            auto_blocked=False,
            scanned_at="2026-01-01T00:00:00+00:00",
        )
        d = record.to_dict()
        assert d["invocation_id"] == "inv-001"
        assert d["detected"] is False
        assert d["secret_types"] == []
        assert d["auto_blocked"] is False

    def test_to_dict_with_detection(self) -> None:
        record = SecretScanRecord(
            invocation_id="inv-002",
            detected=True,
            secret_types=["API_KEY", "BEARER_TOKEN"],
            auto_blocked=True,
            scanned_at="2026-01-01T00:00:00+00:00",
        )
        d = record.to_dict()
        assert d["detected"] is True
        assert "API_KEY" in d["secret_types"]
        assert d["auto_blocked"] is True


class TestGateDecision:
    def test_to_dict_passed(self) -> None:
        decision = GateDecision(
            invocation_id="inv-003",
            confidence=0.91,
            threshold=0.82,
            passed=True,
            routed_to_human=False,
            escalation_queue="",
            decided_at="2026-01-01T00:00:00+00:00",
        )
        d = decision.to_dict()
        assert d["passed"] is True
        assert d["routed_to_human"] is False
        assert d["confidence"] == 0.91

    def test_to_dict_escalated(self) -> None:
        decision = GateDecision(
            invocation_id="inv-004",
            confidence=0.50,
            threshold=0.82,
            passed=False,
            routed_to_human=True,
            escalation_queue="underwriter-review",
            decided_at="2026-01-01T00:00:00+00:00",
        )
        d = decision.to_dict()
        assert d["passed"] is False
        assert d["routed_to_human"] is True
        assert d["escalation_queue"] == "underwriter-review"

    def test_default_gate_id(self) -> None:
        decision = GateDecision(
            invocation_id="inv-005",
            confidence=0.91,
            threshold=0.82,
            passed=True,
            routed_to_human=False,
            escalation_queue="",
            decided_at="2026-01-01T00:00:00+00:00",
        )
        assert decision.gate_id == "loan-summary-confidence"


class TestInvocationRecord:
    def _make_record(self, **kwargs: object) -> InvocationRecord:
        defaults = {
            "invocation_id": "inv-001",
            "application_id": "APP-001",
            "model": "gpt-4o",
            "operation": "loan_summary_generation",
            "status": "ok",
            "duration_ms": 1250.0,
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:00:01.250+00:00",
            "tsc_criteria": ["CC6.1", "CC7.2"],
        }
        defaults.update(kwargs)  # type: ignore[arg-type]
        return InvocationRecord(**defaults)  # type: ignore[arg-type]

    def test_to_dict_basic_fields(self) -> None:
        record = self._make_record()
        d = record.to_dict()
        assert d["invocation_id"] == "inv-001"
        assert d["application_id"] == "APP-001"
        assert d["model"] == "gpt-4o"
        assert d["status"] == "ok"
        assert d["duration_ms"] == 1250.0

    def test_to_dict_pii_records_serialised(self) -> None:
        pii = RedactionRecord(
            document_index=0,
            entity_types_detected=["SSN"],
            entity_count=1,
            redacted=True,
            redacted_at="2026-01-01T00:00:00+00:00",
            pre_hash="abc",
        )
        record = self._make_record(pii_records=[pii])
        d = record.to_dict()
        assert len(d["pii_records"]) == 1
        assert d["pii_records"][0]["entity_count"] == 1

    def test_to_dict_no_optional_fields_when_none(self) -> None:
        record = self._make_record()
        d = record.to_dict()
        assert "secret_record" not in d
        assert "gate_decision" not in d
        assert "error" not in d

    def test_to_dict_error_field_present_when_set(self) -> None:
        record = self._make_record(status="error", error="Something went wrong")
        d = record.to_dict()
        assert d["error"] == "Something went wrong"


class TestPipelineResult:
    def _make_invocation(self) -> InvocationRecord:
        return InvocationRecord(
            invocation_id="inv-001",
            application_id="APP-001",
            model="gpt-4o",
            operation="loan_summary_generation",
            status="ok",
            duration_ms=1000.0,
            started_at="2026-01-01T00:00:00+00:00",
            finished_at="2026-01-01T00:00:01+00:00",
            tsc_criteria=["CC6.1"],
        )

    def test_to_dict_includes_answer(self) -> None:
        result = PipelineResult(
            answer="Approve the loan.",
            invocation=self._make_invocation(),
            routed_to_human=False,
        )
        d = result.to_dict()
        assert d["answer"] == "Approve the loan."

    def test_to_dict_drift_breaches_empty_by_default(self) -> None:
        result = PipelineResult(
            answer="Approve.",
            invocation=self._make_invocation(),
            routed_to_human=False,
        )
        d = result.to_dict()
        assert d["drift_breaches"] == []

    def test_to_dict_drift_breaches_present(self) -> None:
        result = PipelineResult(
            answer="Approve.",
            invocation=self._make_invocation(),
            routed_to_human=False,
            drift_breaches=["response_length", "confidence_score"],
        )
        d = result.to_dict()
        assert "response_length" in d["drift_breaches"]
