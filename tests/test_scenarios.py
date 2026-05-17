"""
Scenario-driven integration tests for LoanSummaryPipeline.

Each test loads a JSON scenario file from tests/data/scenarios/ and runs the
full pipeline against realistic Meridian Lending Co. fixture data.  All
SpanForge SDK clients are mocked so no network access or cloud credentials
are required.

Scenarios
---------
01_clean_application     Happy path — gate passes, no PII, no secrets.
02_pii_redaction         Non-critical PII (email, phone) detected and anonymised.
03_critical_pii_block    SSN in document triggers PIIBlockedError (CC6.6 hard block).
04_low_confidence_hitl   LLM confidence 0.65 < 0.82 threshold → HITL routing (CC7.4).
05_secret_in_output      API key in LLM response → SecretsScanner redacts it (CC6.8).
06_drift_breach          Unusually short response triggers drift alert (CC7.2).
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.exceptions import PIIBlockedError
from soc2_refimpl.pipeline import LoanSummaryPipeline, MockLLMBackend

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCENARIOS_DIR = Path(__file__).parent / "data" / "scenarios"
_SIGNING_KEY = "a" * 64  # 64-char hex → 256-bit HMAC key


def _load_scenario(filename: str) -> dict[str, Any]:
    return json.loads((_SCENARIOS_DIR / filename).read_text(encoding="utf-8"))


def _config(tmp_path: Path) -> PipelineConfig:
    return PipelineConfig(
        api_key="",
        endpoint="",
        project_id="meridian-loan-summary",
        signing_key=_SIGNING_KEY,
        local_fallback=True,
        otel_endpoint="",
        confidence_threshold=0.82,
        drift_z_threshold=3.0,
        audit_output_dir=str(tmp_path),
        model="gpt-4o-mock",
    )


def _build_pii_scan_mock(pii_entry: dict[str, Any]) -> MagicMock:
    """Build a mock PIITextScanResult for one document."""
    scan = MagicMock()
    scan.detected = pii_entry["detected"]
    entities = []
    for entity_type in pii_entry.get("entities", []):
        e = MagicMock()
        e.entity_type = entity_type
        entities.append(e)
    scan.entities = entities
    return scan


def _build_anon_mock(pii_entry: dict[str, Any]) -> MagicMock:
    """Build a mock SFPIIAnonymizeResult."""
    anon = MagicMock()
    anon.anonymized_text = pii_entry.get("anonymized_text") or ""
    return anon


def _build_secrets_mock(s: dict[str, Any]) -> MagicMock:
    """Build a mock SecretsScanResult."""
    result = MagicMock()
    result.detected = s["detected"]
    result.secret_types = s.get("secret_types", [])
    result.auto_blocked = s.get("auto_blocked", False)
    result.redacted_text = s.get("redacted_text") or ""
    result.hits = s.get("hits", [])
    result.confidence_scores = {}
    return result


def _build_gate_mock(g: dict[str, Any]) -> MagicMock:
    """Build a mock GateEvaluationResult."""
    from spanforge.sdk.gate import GateVerdict  # type: ignore[import-untyped]

    verdict_name = g.get("verdict", "PASS")
    result = MagicMock()
    result.verdict = GateVerdict.PASS if verdict_name == "PASS" else GateVerdict.FAIL
    return result


@contextmanager
def _pipeline_context(
    scenario: dict[str, Any],
    tmp_path: Path,
) -> Generator[LoanSummaryPipeline, None, None]:
    """Patch all SpanForge SDK clients and yield a configured pipeline."""
    pii_entries = scenario["pii_mock"]
    sec = scenario["secrets_mock"]
    gate = scenario["gate_mock"]
    drift = scenario["drift_mock"]
    llm_cfg = scenario["llm_mock"]

    # ── Build PII client mock ────────────────────────────────────────────
    # anonymize() is called unconditionally for every document that makes it
    # past the critical-PII check, so the side_effect list must have one entry
    # per document (minus any that would trigger a critical-PII block first).
    mock_pii_client = MagicMock()
    mock_pii_client.scan_text.side_effect = [
        _build_pii_scan_mock(entry) for entry in pii_entries
    ]
    mock_pii_client.anonymize.side_effect = [
        _build_anon_mock(entry) for entry in pii_entries
    ]

    # ── Build Secrets client mock ────────────────────────────────────────
    mock_sec_client = MagicMock()
    mock_sec_client.scan.return_value = _build_secrets_mock(sec)

    # ── Build Gate client mock ───────────────────────────────────────────
    mock_gate_client = MagicMock()
    mock_gate_client.evaluate.return_value = _build_gate_mock(gate)

    # ── Build OTel observe mock ──────────────────────────────────────────
    mock_observe_client = MagicMock()
    mock_observe_client.emit_span.return_value = "test-span-id"

    # ── Build AuditStream / SFAuditClient mocks (avoid SQLite) ──────────
    mock_stream = MagicMock()
    mock_event = MagicMock()
    mock_event.event_id = "evt-test"
    mock_stream.append.return_value = mock_event
    mock_verify = MagicMock()
    mock_verify.valid = True
    mock_verify.first_tampered = None
    mock_verify.gaps = []
    mock_stream.verify.return_value = mock_verify

    mock_audit_store = MagicMock()
    mock_audit_store.append.return_value = None
    mock_audit_store.export.return_value = []

    # ── Build CEC mock ───────────────────────────────────────────────────
    mock_cec = MagicMock()
    mock_cec_result = MagicMock()
    mock_cec_result.bundle_id = "bundle-test"
    mock_cec.build_bundle.return_value = mock_cec_result

    # ── Build Drift mock (inject breach_metrics if scenario requires it) ─
    breach_metrics = drift.get("breach_metrics", [])
    mock_drift_detector = MagicMock()
    mock_drift_detector.record.return_value = []
    mock_drift_detector.in_breach.side_effect = (
        lambda metric_name: metric_name in breach_metrics
    )
    mock_drift_detector.window_stats.return_value = (480.0, 95.0, 50)

    mock_baseline = MagicMock()

    llm = MockLLMBackend(
        response=llm_cfg["response"],
        confidence=llm_cfg["confidence"],
        latency_ms=llm_cfg.get("latency_ms", 0.0),
    )

    config = _config(tmp_path)

    with (
        patch("soc2_refimpl.pii_handler.SFPIIClient", return_value=mock_pii_client),
        patch("soc2_refimpl.secrets_scanner.SFSecretsClient", return_value=mock_sec_client),
        patch("soc2_refimpl.gate.SFGateClient", return_value=mock_gate_client),
        patch("soc2_refimpl.availability.SFObserveClient", return_value=mock_observe_client),
        patch("soc2_refimpl.audit_chain.AuditStream", return_value=mock_stream),
        patch("soc2_refimpl.audit_chain.SFAuditClient", return_value=mock_audit_store),
        patch("soc2_refimpl.compliance.SFCECClient", return_value=mock_cec),
        patch("soc2_refimpl.drift_monitor.DriftDetector", return_value=mock_drift_detector),
        patch("soc2_refimpl.drift_monitor.BehaviouralBaseline", return_value=mock_baseline),
    ):
        yield LoanSummaryPipeline(config, llm=llm)


# ---------------------------------------------------------------------------
# Parametrised scenario tests
# ---------------------------------------------------------------------------

_SCENARIO_FILES = sorted(_SCENARIOS_DIR.glob("*.json"))


@pytest.mark.parametrize(
    "scenario_file",
    _SCENARIO_FILES,
    ids=[f.stem for f in _SCENARIO_FILES],
)
def test_scenario_metadata(scenario_file: Path) -> None:
    """Every scenario file must have the required top-level keys."""
    scenario = json.loads(scenario_file.read_text(encoding="utf-8"))
    for key in ("id", "description", "application_id", "documents", "llm_mock",
                "pii_mock", "secrets_mock", "gate_mock", "expected"):
        assert key in scenario, f"Missing key '{key}' in {scenario_file.name}"
    assert len(scenario["documents"]) == len(scenario["pii_mock"]), (
        "pii_mock must have one entry per document"
    )


# ---------------------------------------------------------------------------
# Scenario 01 — Clean application
# ---------------------------------------------------------------------------

class TestScenarioCleanApplication:
    def test_run_succeeds(self, tmp_path: Path) -> None:
        scenario = _load_scenario("01_clean_application.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(
                scenario["application_id"],
                scenario["documents"],
            )
        assert result is not None

    def test_answer_is_non_empty(self, tmp_path: Path) -> None:
        scenario = _load_scenario("01_clean_application.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert len(result.answer) > 0

    def test_not_routed_to_human(self, tmp_path: Path) -> None:
        scenario = _load_scenario("01_clean_application.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.routed_to_human is False

    def test_no_drift_breach(self, tmp_path: Path) -> None:
        scenario = _load_scenario("01_clean_application.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.drift_breaches == []

    def test_invocation_records_application_id(self, tmp_path: Path) -> None:
        scenario = _load_scenario("01_clean_application.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.application_id == scenario["application_id"]

    def test_invocation_status_is_ok(self, tmp_path: Path) -> None:
        scenario = _load_scenario("01_clean_application.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.status == "ok"


# ---------------------------------------------------------------------------
# Scenario 02 — PII redaction
# ---------------------------------------------------------------------------

class TestScenarioPIIRedaction:
    def test_run_succeeds_despite_pii(self, tmp_path: Path) -> None:
        scenario = _load_scenario("02_pii_redaction.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result is not None

    def test_pii_records_are_created(self, tmp_path: Path) -> None:
        scenario = _load_scenario("02_pii_redaction.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        # One RedactionRecord per document
        assert len(result.invocation.pii_records) == len(scenario["documents"])

    def test_pii_redacted_flag_set(self, tmp_path: Path) -> None:
        scenario = _load_scenario("02_pii_redaction.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        # RedactionRecord.redacted is True when entity_types_detected is non-empty
        redacted = [r for r in result.invocation.pii_records if r.redacted]
        assert len(redacted) == 2

    def test_pipeline_not_blocked(self, tmp_path: Path) -> None:
        """Non-critical PII must not raise PIIBlockedError."""
        scenario = _load_scenario("02_pii_redaction.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            # Should not raise
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.status != "error"


# ---------------------------------------------------------------------------
# Scenario 03 — Critical PII block (SSN)
# ---------------------------------------------------------------------------

class TestScenarioCriticalPIIBlock:
    def test_raises_pii_blocked_error(self, tmp_path: Path) -> None:
        scenario = _load_scenario("03_critical_pii_block.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            with pytest.raises(PIIBlockedError) as exc_info:
                pipeline.run(scenario["application_id"], scenario["documents"])
        assert "SSN" in exc_info.value.entity_types

    def test_exception_carries_tsc_criterion(self, tmp_path: Path) -> None:
        scenario = _load_scenario("03_critical_pii_block.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            with pytest.raises(PIIBlockedError) as exc_info:
                pipeline.run(scenario["application_id"], scenario["documents"])
        assert exc_info.value.tsc_criterion == "CC6.6"

    def test_llm_is_never_called(self, tmp_path: Path) -> None:
        scenario = _load_scenario("03_critical_pii_block.json")
        call_count = [0]
        original_response = scenario["llm_mock"]["response"]

        class TrackingLLM:
            def generate(self, prompt: str) -> tuple[str, float]:
                call_count[0] += 1
                return original_response, 0.88

        with _pipeline_context(scenario, tmp_path) as pipeline:
            pipeline._llm = TrackingLLM()  # type: ignore[attr-defined]
            with pytest.raises(PIIBlockedError):
                pipeline.run(scenario["application_id"], scenario["documents"])

        assert call_count[0] == 0, "LLM must not be called when PII blocks the pipeline"


# ---------------------------------------------------------------------------
# Scenario 04 — Low confidence → HITL routing
# ---------------------------------------------------------------------------

class TestScenarioLowConfidenceHITL:
    def test_run_does_not_raise(self, tmp_path: Path) -> None:
        """Low confidence must not raise — it routes to human review instead."""
        scenario = _load_scenario("04_low_confidence_hitl.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result is not None

    def test_routed_to_human_is_true(self, tmp_path: Path) -> None:
        scenario = _load_scenario("04_low_confidence_hitl.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.routed_to_human is True

    def test_invocation_status_is_escalated(self, tmp_path: Path) -> None:
        scenario = _load_scenario("04_low_confidence_hitl.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.status == "escalated"

    def test_answer_is_still_returned(self, tmp_path: Path) -> None:
        """Escalated responses still return the answer for reviewer context."""
        scenario = _load_scenario("04_low_confidence_hitl.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert len(result.answer) > 0

    def test_gate_decision_recorded(self, tmp_path: Path) -> None:
        scenario = _load_scenario("04_low_confidence_hitl.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.gate_decision is not None
        assert result.invocation.gate_decision.passed is False


# ---------------------------------------------------------------------------
# Scenario 05 — Secret in LLM output
# ---------------------------------------------------------------------------

class TestScenarioSecretInOutput:
    def test_run_succeeds(self, tmp_path: Path) -> None:
        scenario = _load_scenario("05_secret_in_output.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result is not None

    def test_answer_is_redacted(self, tmp_path: Path) -> None:
        """When secrets are detected, the raw LLM response must not be returned."""
        scenario = _load_scenario("05_secret_in_output.json")
        raw_response = scenario["llm_mock"]["response"]
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.answer != raw_response

    def test_secret_record_shows_detected(self, tmp_path: Path) -> None:
        scenario = _load_scenario("05_secret_in_output.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.secret_record is not None
        assert result.invocation.secret_record.detected is True

    def test_not_routed_to_human(self, tmp_path: Path) -> None:
        scenario = _load_scenario("05_secret_in_output.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.routed_to_human is False


# ---------------------------------------------------------------------------
# Scenario 06 — Drift breach
# ---------------------------------------------------------------------------

class TestScenarioDriftBreach:
    def test_run_succeeds(self, tmp_path: Path) -> None:
        scenario = _load_scenario("06_drift_breach.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result is not None

    def test_drift_breach_reported(self, tmp_path: Path) -> None:
        scenario = _load_scenario("06_drift_breach.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert len(result.drift_breaches) > 0

    def test_response_length_is_breaching_metric(self, tmp_path: Path) -> None:
        scenario = _load_scenario("06_drift_breach.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert "response_length" in result.drift_breaches

    def test_run_still_succeeds_despite_breach(self, tmp_path: Path) -> None:
        """Drift breach is an alert, not a hard block — pipeline completes."""
        scenario = _load_scenario("06_drift_breach.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.invocation.status == "ok"

    def test_not_routed_to_human(self, tmp_path: Path) -> None:
        scenario = _load_scenario("06_drift_breach.json")
        with _pipeline_context(scenario, tmp_path) as pipeline:
            result = pipeline.run(scenario["application_id"], scenario["documents"])
        assert result.routed_to_human is False
