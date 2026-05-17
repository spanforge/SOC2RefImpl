"""Tests for soc2_refimpl.audit_chain (TSC CC9.2)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from soc2_refimpl.audit_chain import AuditChain
from soc2_refimpl.exceptions import AuditChainError
from soc2_refimpl.models import (
    GateDecision,
    InvocationRecord,
    RedactionRecord,
    SecretScanRecord,
)


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


def _make_invocation() -> InvocationRecord:
    return InvocationRecord(
        invocation_id="inv-001",
        application_id="APP-001",
        model="gpt-4o",
        operation="loan_summary_generation",
        status="ok",
        duration_ms=1250.0,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01.250+00:00",
        tsc_criteria=["CC6.1", "CC7.2"],
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


def _make_gate_decision() -> GateDecision:
    return GateDecision(
        invocation_id="inv-001",
        confidence=0.91,
        threshold=0.82,
        passed=True,
        routed_to_human=False,
        escalation_queue="",
        decided_at="2026-01-01T00:00:00+00:00",
    )


class TestAuditChainInit:
    def test_initialises_without_error(self, base_config: object) -> None:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        assert chain is not None

    def test_has_stream_attribute(self, base_config: object) -> None:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        assert hasattr(chain, "_stream")  # type: ignore[attr-defined]


class TestAuditChainRecordMethods:
    def _make_mock_stream(self) -> MagicMock:
        stream = MagicMock()
        event = MagicMock()
        event.event_id = "evt-001"
        stream.append.return_value = event
        return stream

    def _make_mock_store(self) -> MagicMock:
        store = MagicMock()
        store.append.return_value = None
        return store

    def _make_chain_with_mocks(self, base_config: object) -> AuditChain:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        chain._stream = self._make_mock_stream()  # type: ignore[attr-defined]
        chain._store = self._make_mock_store()  # type: ignore[attr-defined]
        return chain

    def test_record_invocation_does_not_raise(self, base_config: object) -> None:
        chain = self._make_chain_with_mocks(base_config)
        chain.record_invocation(_make_invocation())  # should not raise

    def test_record_pii_does_not_raise(self, base_config: object) -> None:
        chain = self._make_chain_with_mocks(base_config)
        chain.record_pii([_make_redaction()], invocation_id="inv-001")

    def test_record_secrets_does_not_raise(self, base_config: object) -> None:
        chain = self._make_chain_with_mocks(base_config)
        chain.record_secrets(_make_secret())

    def test_record_gate_does_not_raise(self, base_config: object) -> None:
        chain = self._make_chain_with_mocks(base_config)
        chain.record_gate(_make_gate_decision())

    def test_record_drift_does_not_raise(self, base_config: object) -> None:
        chain = self._make_chain_with_mocks(base_config)
        payload = {"metric_name": "response_length", "tsc_criterion": "CC7.2"}
        chain.record_drift(payload, invocation_id="inv-001")

    def test_stream_append_called_once_per_record(
        self, base_config: object
    ) -> None:
        chain = self._make_chain_with_mocks(base_config)
        chain.record_invocation(_make_invocation())
        chain._stream.append.assert_called_once()  # type: ignore[attr-defined]

    def test_store_failure_is_non_fatal(self, base_config: object) -> None:
        """AuditStore failures must not propagate — chain continues."""
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        chain._stream = self._make_mock_stream()  # type: ignore[attr-defined]
        mock_store = MagicMock()
        mock_store.append.side_effect = Exception("schema error")
        chain._store = mock_store  # type: ignore[attr-defined]
        # Should not raise
        chain.record_invocation(_make_invocation())


class TestAuditChainVerify:
    def _make_chain_with_valid_chain(self, base_config: object) -> AuditChain:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        verify_result = MagicMock()
        verify_result.valid = True
        verify_result.first_tampered = None
        verify_result.gaps = []
        verify_result.tampered_count = 0
        chain._stream = MagicMock()  # type: ignore[attr-defined]
        chain._stream.verify.return_value = verify_result  # type: ignore[attr-defined]
        return chain

    def _make_chain_with_tampered_chain(self, base_config: object) -> AuditChain:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        verify_result = MagicMock()
        verify_result.valid = False
        verify_result.first_tampered = "event-3"
        verify_result.gaps = ["gap-1"]
        verify_result.tampered_count = 1
        chain._stream = MagicMock()  # type: ignore[attr-defined]
        chain._stream.verify.return_value = verify_result  # type: ignore[attr-defined]
        return chain

    def test_verify_returns_valid_result(self, base_config: object) -> None:
        chain = self._make_chain_with_valid_chain(base_config)
        result = chain.verify()
        assert result.valid is True

    def test_verify_raises_on_tampered_chain(self, base_config: object) -> None:
        chain = self._make_chain_with_tampered_chain(base_config)
        with pytest.raises(AuditChainError) as exc_info:
            chain.verify()
        assert exc_info.value.first_tampered == "event-3"
        assert exc_info.value.tsc_criterion == "CC9.2"

    def test_verify_gaps_in_exception(self, base_config: object) -> None:
        chain = self._make_chain_with_tampered_chain(base_config)
        with pytest.raises(AuditChainError) as exc_info:
            chain.verify()
        assert "gap-1" in exc_info.value.gaps


class TestAuditChainExportJsonl:
    def test_export_jsonl_creates_file(self, base_config: object) -> None:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        # Mock the store to return some records
        mock_store = MagicMock()
        mock_store.export.return_value = [
            {"invocation_id": "inv-001", "event_type": "TRACE_SPAN_COMPLETED"}
        ]
        chain._store = mock_store  # type: ignore[attr-defined]

        output_path = chain.export_jsonl()
        assert output_path.exists()
        assert output_path.suffix == ".jsonl"

    def test_export_jsonl_contains_valid_json_lines(
        self, base_config: object
    ) -> None:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        mock_store = MagicMock()
        mock_store.export.return_value = [
            {"invocation_id": "inv-001", "key": "value"},
            {"invocation_id": "inv-002", "key": "data"},
        ]
        chain._store = mock_store  # type: ignore[attr-defined]

        output_path = chain.export_jsonl()
        lines = output_path.read_text(encoding="utf-8").strip().splitlines()
        # Each line must be valid JSON
        for line in lines:
            obj = json.loads(line)
            assert isinstance(obj, dict)

    def test_export_jsonl_fallback_on_store_error(
        self, base_config: object
    ) -> None:
        """When store.export fails, export should still produce an empty file."""
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        mock_store = MagicMock()
        mock_store.export.side_effect = Exception("export failed")
        chain._store = mock_store  # type: ignore[attr-defined]

        output_path = chain.export_jsonl()
        assert output_path.exists()

    def test_close_calls_store_close(self, base_config: object) -> None:
        chain = AuditChain(base_config)  # type: ignore[arg-type]
        mock_store = MagicMock()
        chain._store = mock_store  # type: ignore[attr-defined]
        chain.close()
        mock_store.close.assert_called_once()
