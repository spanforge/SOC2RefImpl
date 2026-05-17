"""Tests for soc2_refimpl.pipeline (LoanSummaryPipeline — main orchestrator)."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from soc2_refimpl.exceptions import AuditChainError, PIIBlockedError
from soc2_refimpl.models import GateDecision, PipelineResult, SecretScanRecord, utc_now_iso
from soc2_refimpl.pipeline import LoanSummaryPipeline, MockLLMBackend


# ---------------------------------------------------------------------------
# Module-level autouse patch — prevents AuditStream / SFAuditClient from
# opening real SQLite connections during tests (avoids ResourceWarning).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_spanforge_audit(monkeypatch: pytest.MonkeyPatch) -> None:  # type: ignore[return]
    """Replace AuditStream and SFAuditClient with mocks for every test."""
    mock_stream = MagicMock()
    mock_event = MagicMock()
    mock_event.event_id = "evt-auto"
    mock_stream.append.return_value = mock_event

    mock_verify = MagicMock()
    mock_verify.valid = True
    mock_verify.first_tampered = None
    mock_verify.gaps = []
    mock_verify.tampered_count = 0
    mock_stream.verify.return_value = mock_verify

    mock_store = MagicMock()
    mock_store.append.return_value = None
    mock_store.export.return_value = []

    with (
        patch("soc2_refimpl.audit_chain.AuditStream", return_value=mock_stream),
        patch("soc2_refimpl.audit_chain.SFAuditClient", return_value=mock_store),
    ):
        yield

# ---------------------------------------------------------------------------
# MockLLMBackend tests
# ---------------------------------------------------------------------------


class TestMockLLMBackend:
    def test_generate_returns_tuple(self) -> None:
        llm = MockLLMBackend(response="Approve.", confidence=0.91)
        answer, confidence = llm.generate("some prompt")
        assert isinstance(answer, str)
        assert isinstance(confidence, float)

    def test_generate_returns_configured_response(self) -> None:
        llm = MockLLMBackend(response="My response.", confidence=0.91)
        answer, _ = llm.generate("prompt")
        assert answer == "My response."

    def test_generate_returns_configured_confidence(self) -> None:
        llm = MockLLMBackend(response="R", confidence=0.77)
        _, confidence = llm.generate("prompt")
        assert confidence == pytest.approx(0.77)

    def test_generate_no_sleep_at_zero_latency(self) -> None:
        llm = MockLLMBackend(response="R", confidence=0.91, latency_ms=0.0)
        start = time.monotonic()
        llm.generate("prompt")
        elapsed = (time.monotonic() - start) * 1000
        assert elapsed < 500

    def test_generate_with_latency(self) -> None:
        llm = MockLLMBackend(response="R", confidence=0.91, latency_ms=100.0)
        start = time.monotonic()
        llm.generate("prompt")
        elapsed = (time.monotonic() - start) * 1000
        assert elapsed >= 50


# ---------------------------------------------------------------------------
# LoanSummaryPipeline init tests
# ---------------------------------------------------------------------------


class TestLoanSummaryPipelineInit:
    def test_initialises_without_error(
        self, base_config: object, mock_llm: MockLLMBackend
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]
        assert pipeline is not None

    def test_has_pii_attribute(
        self, base_config: object, mock_llm: MockLLMBackend
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]
        assert pipeline._pii is not None  # type: ignore[attr-defined]

    def test_has_audit_attribute(
        self, base_config: object, mock_llm: MockLLMBackend
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]
        assert pipeline._audit is not None  # type: ignore[attr-defined]

    def test_default_llm_is_mock(self, base_config: object) -> None:
        pipeline = LoanSummaryPipeline(base_config)  # type: ignore[arg-type]
        assert isinstance(pipeline._llm, MockLLMBackend)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Helper to create a fully-mocked pipeline for run() tests
# ---------------------------------------------------------------------------


def _make_pipeline_with_mocks(
    config: object,
    llm: MockLLMBackend,
    documents: list[str],
    *,
    gate_passes: bool = True,
    drift_breaches: list[str] | None = None,
) -> LoanSummaryPipeline:
    """Return a pipeline with all SpanForge clients replaced by MagicMocks."""
    from soc2_refimpl.audit_chain import AuditChain
    from soc2_refimpl.availability import AvailabilityMonitor
    from soc2_refimpl.compliance import ComplianceExporter
    from soc2_refimpl.drift_monitor import DriftMonitor
    from soc2_refimpl.gate import ComplianceGate
    from soc2_refimpl.pii_handler import PIIHandler
    from soc2_refimpl.secrets_scanner import SecretsScanner

    pipeline = LoanSummaryPipeline(config, llm)  # type: ignore[arg-type]

    # Mock PII — return documents unchanged
    mock_pii = MagicMock(spec=PIIHandler)
    mock_pii.process_documents.return_value = (documents, [])
    pipeline._pii = mock_pii  # type: ignore[attr-defined]

    # Mock secrets scanner — no secrets detected
    mock_secret_obj = SecretScanRecord(
        invocation_id="inv-x",
        detected=False,
        secret_types=[],
        auto_blocked=False,
        scanned_at=utc_now_iso(),
    )
    mock_secrets = MagicMock(spec=SecretsScanner)
    mock_secrets.scan.return_value = ("safe answer", mock_secret_obj)
    pipeline._secrets = mock_secrets  # type: ignore[attr-defined]

    # Mock drift monitor
    mock_drift = MagicMock(spec=DriftMonitor)
    mock_drift.observe.return_value = drift_breaches or []
    mock_drift.make_alert_payload.return_value = {
        "metric_name": "response_length",
        "tsc_criterion": "CC7.2",
        "alerted_at": utc_now_iso(),
    }
    pipeline._drift = mock_drift  # type: ignore[attr-defined]

    # Mock gate
    mock_gate_obj = GateDecision(
        invocation_id="inv-x",
        confidence=0.91,
        threshold=0.82,
        passed=gate_passes,
        routed_to_human=not gate_passes,
        escalation_queue="" if gate_passes else "underwriter-review",
        decided_at=utc_now_iso(),
    )
    mock_gate = MagicMock(spec=ComplianceGate)
    mock_gate.evaluate.return_value = mock_gate_obj
    pipeline._gate = mock_gate  # type: ignore[attr-defined]

    # Mock audit chain
    mock_audit = MagicMock(spec=AuditChain)
    verify_result = MagicMock()
    verify_result.valid = True
    verify_result.tampered_count = 0
    verify_result.gaps = []
    verify_result.first_tampered = None
    mock_audit.verify.return_value = verify_result
    pipeline._audit = mock_audit  # type: ignore[attr-defined]

    # Mock availability
    mock_avail = MagicMock(spec=AvailabilityMonitor)
    mock_avail.record_invocation.return_value = "span-001"
    pipeline._availability = mock_avail  # type: ignore[attr-defined]

    # Mock compliance exporter
    pipeline._compliance = MagicMock(spec=ComplianceExporter)  # type: ignore[attr-defined]

    return pipeline


# ---------------------------------------------------------------------------
# LoanSummaryPipeline.run() tests
# ---------------------------------------------------------------------------


class TestLoanSummaryPipelineRun:
    def test_run_returns_pipeline_result(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("APP-001", safe_documents)
        assert isinstance(result, PipelineResult)

    def test_run_result_has_answer(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("APP-001", safe_documents)
        assert isinstance(result.answer, str)
        assert len(result.answer) > 0

    def test_run_result_has_invocation(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("APP-001", safe_documents)
        assert result.invocation is not None

    def test_run_pass_not_routed_to_human(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(
            base_config, mock_llm, safe_documents, gate_passes=True
        )
        result = pipeline.run("APP-001", safe_documents)
        assert result.routed_to_human is False

    def test_run_block_routed_to_human(
        self,
        base_config: object,
        low_confidence_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(
            base_config, low_confidence_llm, safe_documents, gate_passes=False
        )
        result = pipeline.run("APP-001", safe_documents)
        assert result.routed_to_human is True

    def test_run_invocation_has_application_id(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("MY-APP-42", safe_documents)
        assert result.invocation.application_id == "MY-APP-42"

    def test_run_invocation_status_ok_on_success(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("APP-001", safe_documents)
        assert result.invocation.status == "ok"

    def test_run_raises_pii_blocked_error(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
    ) -> None:
        """When PII handler raises PIIBlockedError, pipeline must propagate it."""
        from soc2_refimpl.audit_chain import AuditChain
        from soc2_refimpl.availability import AvailabilityMonitor
        from soc2_refimpl.pii_handler import PIIHandler

        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]

        mock_pii = MagicMock(spec=PIIHandler)
        mock_pii.process_documents.side_effect = PIIBlockedError(["SSN"])
        pipeline._pii = mock_pii  # type: ignore[attr-defined]

        mock_audit = MagicMock(spec=AuditChain)
        pipeline._audit = mock_audit  # type: ignore[attr-defined]

        mock_avail = MagicMock(spec=AvailabilityMonitor)
        mock_avail.record_invocation.return_value = "span-001"
        pipeline._availability = mock_avail  # type: ignore[attr-defined]

        pipeline._compliance = MagicMock()  # type: ignore[attr-defined]

        with pytest.raises(PIIBlockedError):
            pipeline.run("APP-002", ["SSN: 123-45-6789"])

    def test_run_drift_breaches_in_result(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(
            base_config,
            mock_llm,
            safe_documents,
            drift_breaches=["response_length"],
        )
        result = pipeline.run("APP-003", safe_documents)
        assert "response_length" in result.drift_breaches

    def test_run_confidence_override(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("APP-004", safe_documents, confidence_override=0.99)
        assert isinstance(result, PipelineResult)

    def test_run_audit_record_invocation_called(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        pipeline.run("APP-005", safe_documents)
        pipeline._audit.record_invocation.assert_called_once()  # type: ignore[attr-defined]

    def test_run_availability_record_called(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        pipeline.run("APP-006", safe_documents)
        pipeline._availability.record_invocation.assert_called_once()  # type: ignore[attr-defined]

    def test_run_invocation_tsc_criteria_present(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
        safe_documents: list[str],
    ) -> None:
        pipeline = _make_pipeline_with_mocks(base_config, mock_llm, safe_documents)
        result = pipeline.run("APP-007", safe_documents)
        assert len(result.invocation.tsc_criteria) > 0


# ---------------------------------------------------------------------------
# LoanSummaryPipeline export and verify
# ---------------------------------------------------------------------------


class TestLoanSummaryPipelineExportAndVerify:
    def test_export_evidence_bundle_returns_dict(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]

        mock_audit = MagicMock()
        verify_result = MagicMock()
        verify_result.valid = True
        verify_result.tampered_count = 0
        verify_result.gaps = []
        verify_result.first_tampered = None
        mock_audit.verify.return_value = verify_result
        pipeline._audit = mock_audit  # type: ignore[attr-defined]

        mock_compliance = MagicMock()
        mock_compliance.export_local.return_value = {
            "invocations": Path("/tmp/invocations.jsonl"),
            "manifest": Path("/tmp/manifest.json"),
        }
        pipeline._compliance = mock_compliance  # type: ignore[attr-defined]

        bundle = pipeline.export_evidence_bundle()
        assert isinstance(bundle, dict)

    def test_verify_audit_chain_returns_true(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]
        mock_audit = MagicMock()
        verify_result = MagicMock()
        verify_result.valid = True
        mock_audit.verify.return_value = verify_result
        pipeline._audit = mock_audit  # type: ignore[attr-defined]

        result = pipeline.verify_audit_chain()
        assert result is True

    def test_verify_audit_chain_false_on_audit_chain_error(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]
        mock_audit = MagicMock()
        mock_audit.verify.side_effect = AuditChainError(
            first_tampered="evt-3", gaps=[]
        )
        pipeline._audit = mock_audit  # type: ignore[attr-defined]

        result = pipeline.verify_audit_chain()
        assert result is False

    def test_close_calls_audit_close(
        self,
        base_config: object,
        mock_llm: MockLLMBackend,
    ) -> None:
        pipeline = LoanSummaryPipeline(base_config, mock_llm)  # type: ignore[arg-type]
        mock_audit = MagicMock()
        pipeline._audit = mock_audit  # type: ignore[attr-defined]
        pipeline.close()
        mock_audit.close.assert_called_once()
