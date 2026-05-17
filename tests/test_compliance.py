"""Tests for soc2_refimpl.compliance (ComplianceExporter)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from soc2_refimpl.audit_chain import AuditChain
from soc2_refimpl.availability import AvailabilityMonitor
from soc2_refimpl.compliance import ComplianceExporter
from soc2_refimpl.models import (
    GateDecision,
    InvocationRecord,
    RedactionRecord,
    SecretScanRecord,
)


def _make_invocation(inv_id: str = "inv-001") -> InvocationRecord:
    return InvocationRecord(
        invocation_id=inv_id,
        application_id="APP-001",
        model="gpt-4o",
        operation="loan_summary_generation",
        status="ok",
        duration_ms=1250.0,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01.250+00:00",
        tsc_criteria=["CC6.1"],
    )


def _make_redaction() -> RedactionRecord:
    return RedactionRecord(
        document_index=0,
        entity_types_detected=["EMAIL_ADDRESS"],
        entity_count=1,
        redacted=True,
        redacted_at="2026-01-01T00:00:00+00:00",
        pre_hash="abc123",
    )


def _make_secret() -> SecretScanRecord:
    return SecretScanRecord(
        invocation_id="inv-001",
        detected=False,
        secret_types=[],
        auto_blocked=False,
        scanned_at="2026-01-01T00:00:00+00:00",
    )


def _make_gate_decision(passed: bool = True) -> GateDecision:
    return GateDecision(
        invocation_id="inv-001",
        confidence=0.91,
        threshold=0.82,
        passed=passed,
        routed_to_human=not passed,
        escalation_queue="" if passed else "underwriter-review",
        decided_at="2026-01-01T00:00:00+00:00",
    )


@pytest.fixture
def mock_audit_chain(base_config: object) -> AuditChain:
    chain = MagicMock(spec=AuditChain)
    chain.export_jsonl.return_value = Path("/tmp/audit_chain.jsonl")
    return chain  # type: ignore[return-value]


@pytest.fixture
def mock_availability(base_config: object) -> AvailabilityMonitor:
    from soc2_refimpl.availability import AvailabilityStats
    monitor = MagicMock(spec=AvailabilityMonitor)
    stats = AvailabilityStats(
        total_invocations=1,
        error_count=0,
        uptime_pct=100.0,
        p50_ms=1250.0,
        p95_ms=1250.0,
        p99_ms=1250.0,
    )
    monitor.get_stats.return_value = stats
    return monitor  # type: ignore[return-value]


@pytest.fixture
def exporter(
    base_config: object,
    mock_audit_chain: AuditChain,
    mock_availability: AvailabilityMonitor,
) -> ComplianceExporter:
    return ComplianceExporter(
        base_config,  # type: ignore[arg-type]
        audit_chain=mock_audit_chain,
        availability_monitor=mock_availability,
    )


class TestComplianceExporterAddMethods:
    def test_add_invocation(self, exporter: ComplianceExporter) -> None:
        inv = _make_invocation()
        exporter.add_invocation(inv)
        # Should not raise; check internal list grew
        assert len(exporter._invocations) == 1  # type: ignore[attr-defined]

    def test_add_pii_records(self, exporter: ComplianceExporter) -> None:
        exporter.add_pii_records([_make_redaction()])
        assert len(exporter._pii_records) == 1  # type: ignore[attr-defined]

    def test_add_secret_record(self, exporter: ComplianceExporter) -> None:
        exporter.add_secret_record(_make_secret())
        assert len(exporter._secret_records) == 1  # type: ignore[attr-defined]

    def test_add_gate_decision_passed(self, exporter: ComplianceExporter) -> None:
        exporter.add_gate_decision(_make_gate_decision(passed=True))
        # All gate decisions are stored (passed or blocked)
        assert len(exporter._gate_decisions) == 1  # type: ignore[attr-defined]

    def test_add_gate_decision_blocked(self, exporter: ComplianceExporter) -> None:
        exporter.add_gate_decision(_make_gate_decision(passed=False))
        assert len(exporter._gate_decisions) == 1  # type: ignore[attr-defined]

    def test_add_drift_alert(self, exporter: ComplianceExporter) -> None:
        payload = {"metric_name": "response_length", "tsc_criterion": "CC7.2"}
        exporter.add_drift_alert(payload)
        assert len(exporter._drift_alerts) == 1  # type: ignore[attr-defined]

    def test_multiple_invocations_accumulate(
        self, exporter: ComplianceExporter
    ) -> None:
        for i in range(5):
            exporter.add_invocation(_make_invocation(f"inv-{i:03d}"))
        assert len(exporter._invocations) == 5  # type: ignore[attr-defined]


class TestComplianceExporterExportLocal:
    def test_export_local_returns_dict_of_paths(
        self, exporter: ComplianceExporter
    ) -> None:
        exporter.add_invocation(_make_invocation())
        exporter.add_pii_records([_make_redaction()])
        exporter.add_secret_record(_make_secret())
        exporter.add_gate_decision(_make_gate_decision())

        paths = exporter.export_local()
        assert isinstance(paths, dict)
        assert len(paths) > 0

    def test_export_local_creates_invocations_jsonl(
        self, exporter: ComplianceExporter
    ) -> None:
        exporter.add_invocation(_make_invocation())
        paths = exporter.export_local()
        assert "invocations.jsonl" in paths
        assert paths["invocations.jsonl"].exists()

    def test_export_local_invocations_valid_json(
        self, exporter: ComplianceExporter
    ) -> None:
        exporter.add_invocation(_make_invocation())
        paths = exporter.export_local()
        lines = paths["invocations.jsonl"].read_text(encoding="utf-8").strip().splitlines()
        for line in lines:
            obj = json.loads(line)
            assert "invocation_id" in obj

    def test_export_local_creates_manifest(
        self, exporter: ComplianceExporter
    ) -> None:
        paths = exporter.export_local()
        assert "manifest.json" in paths
        assert paths["manifest.json"].exists()

    def test_manifest_has_tsc_criteria(
        self, exporter: ComplianceExporter
    ) -> None:
        paths = exporter.export_local()
        manifest = json.loads(paths["manifest.json"].read_text(encoding="utf-8"))
        assert "tsc_mapping" in manifest

    def test_export_local_pii_records_jsonl(
        self, exporter: ComplianceExporter
    ) -> None:
        exporter.add_pii_records([_make_redaction(), _make_redaction()])
        paths = exporter.export_local()
        assert "pii_redaction.jsonl" in paths
        lines = paths["pii_redaction.jsonl"].read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

    def test_export_local_availability_stats(
        self, exporter: ComplianceExporter
    ) -> None:
        paths = exporter.export_local()
        assert "availability_stats.json" in paths
        stats_obj = json.loads(
            paths["availability_stats.json"].read_text(encoding="utf-8")
        )
        assert "total_invocations" in stats_obj

    def test_export_can_be_called_multiple_times(
        self, exporter: ComplianceExporter
    ) -> None:
        exporter.add_invocation(_make_invocation("inv-001"))
        exporter.export_local()
        exporter.add_invocation(_make_invocation("inv-002"))
        paths = exporter.export_local()
        lines = paths["invocations.jsonl"].read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2


class TestComplianceExporterBuildCloudBundle:
    def test_returns_none_when_no_api_key(
        self, exporter: ComplianceExporter
    ) -> None:
        result = exporter.build_cloud_bundle("2026-01-01", "2026-03-31")
        assert result is None

    def test_returns_bundle_id_when_api_key_set(
        self,
        high_confidence_config: object,
        mock_audit_chain: AuditChain,
        mock_availability: AvailabilityMonitor,
    ) -> None:
        from soc2_refimpl.config import PipelineConfig

        cfg = PipelineConfig(
            api_key="sf-valid-api-key",
            signing_key="a" * 64,
            local_fallback=False,
        )
        exporter = ComplianceExporter(cfg, mock_audit_chain, mock_availability)

        mock_cec = MagicMock()
        bundle_result = MagicMock()
        bundle_result.bundle_id = "bundle-xyz-123"
        mock_cec.build_bundle.return_value = bundle_result
        exporter._cec = mock_cec  # type: ignore[attr-defined]

        result = exporter.build_cloud_bundle("2026-01-01", "2026-03-31")
        assert result == "bundle-xyz-123"
