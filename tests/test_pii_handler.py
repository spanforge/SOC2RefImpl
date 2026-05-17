"""Tests for soc2_refimpl.pii_handler (TSC CC6.6)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from soc2_refimpl.exceptions import PIIBlockedError
from soc2_refimpl.models import RedactionRecord
from soc2_refimpl.pii_handler import PIIHandler, _sha256


class TestSha256:
    def test_returns_hex_string(self) -> None:
        result = _sha256("hello")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 = 32 bytes = 64 hex chars

    def test_deterministic(self) -> None:
        assert _sha256("test") == _sha256("test")

    def test_different_inputs_different_hashes(self) -> None:
        assert _sha256("abc") != _sha256("xyz")


class TestPIIHandlerInit:
    def test_initialises_without_error(self, base_config: object) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        assert handler is not None

    def test_uses_local_fallback(self, base_config: object) -> None:
        # Should not raise even without SpanForge cloud credentials
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        assert handler._client is not None  # type: ignore[attr-defined]


class TestPIIHandlerProcessDocuments:
    def test_safe_documents_returned_unchanged_length(
        self,
        base_config: object,
        safe_documents: list[str],
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        clean_docs, records = handler.process_documents(safe_documents)
        assert len(clean_docs) == len(safe_documents)
        assert len(records) == len(safe_documents)

    def test_records_have_correct_document_index(
        self,
        base_config: object,
        safe_documents: list[str],
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        _, records = handler.process_documents(safe_documents)
        for i, record in enumerate(records):
            assert record.document_index == i

    def test_records_have_pre_hash(
        self,
        base_config: object,
        safe_documents: list[str],
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        _, records = handler.process_documents(safe_documents)
        for i, record in enumerate(records):
            expected_hash = _sha256(safe_documents[i])
            assert record.pre_hash == expected_hash

    def test_empty_document_list(self, base_config: object) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        clean_docs, records = handler.process_documents([])
        assert clean_docs == []
        assert records == []

    def test_single_document(self, base_config: object) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        clean_docs, records = handler.process_documents(["Single document text."])
        assert len(clean_docs) == 1
        assert len(records) == 1
        assert records[0].document_index == 0

    def test_records_are_redaction_record_type(
        self,
        base_config: object,
        safe_documents: list[str],
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        _, records = handler.process_documents(safe_documents)
        for record in records:
            assert isinstance(record, RedactionRecord)

    def test_redacted_at_is_set(
        self,
        base_config: object,
        safe_documents: list[str],
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]
        _, records = handler.process_documents(safe_documents)
        for record in records:
            assert record.redacted_at != ""
            assert "+00:00" in record.redacted_at or record.redacted_at.endswith("Z")

    def test_critical_pii_raises_blocked_error(
        self,
        base_config: object,
    ) -> None:
        """Documents with SSN must trigger PIIBlockedError (CC6.6)."""
        handler = PIIHandler(base_config)  # type: ignore[arg-type]

        # Mock scan_text to return an SSN entity
        mock_entity = MagicMock()
        mock_entity.entity_type = "SSN"
        mock_scan = MagicMock()
        mock_scan.entities = [mock_entity]
        mock_scan.detected = True

        with patch.object(handler._client, "scan_text", return_value=mock_scan):  # type: ignore[attr-defined]
            with pytest.raises(PIIBlockedError) as exc_info:
                handler.process_documents(["SSN is 123-45-6789"])

        assert "SSN" in exc_info.value.entity_types
        assert exc_info.value.tsc_criterion == "CC6.6"

    def test_critical_account_number_raises_blocked_error(
        self,
        base_config: object,
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]

        mock_entity = MagicMock()
        mock_entity.entity_type = "ACCOUNT_NUMBER"
        mock_scan = MagicMock()
        mock_scan.entities = [mock_entity]

        with patch.object(handler._client, "scan_text", return_value=mock_scan):  # type: ignore[attr-defined]
            with pytest.raises(PIIBlockedError) as exc_info:
                handler.process_documents(["Account: 9876543210"])

        assert "ACCOUNT_NUMBER" in exc_info.value.entity_types

    def test_non_critical_pii_does_not_block(
        self,
        base_config: object,
    ) -> None:
        """Email addresses are flagged but do not block processing."""
        handler = PIIHandler(base_config)  # type: ignore[arg-type]

        mock_entity = MagicMock()
        mock_entity.entity_type = "EMAIL_ADDRESS"
        mock_scan = MagicMock()
        mock_scan.entities = [mock_entity]
        mock_anon = MagicMock()
        mock_anon.anonymized_text = "Contact: <EMAIL_ADDRESS>"

        with (
            patch.object(handler._client, "scan_text", return_value=mock_scan),  # type: ignore[attr-defined]
            patch.object(handler._client, "anonymize", return_value=mock_anon),  # type: ignore[attr-defined]
        ):
            clean_docs, records = handler.process_documents(["Contact: user@example.com"])

        assert len(clean_docs) == 1
        assert records[0].entity_types_detected == ["EMAIL_ADDRESS"]
        assert records[0].redacted is True

    def test_no_entities_detected(
        self,
        base_config: object,
    ) -> None:
        handler = PIIHandler(base_config)  # type: ignore[arg-type]

        mock_scan = MagicMock()
        mock_scan.entities = []
        mock_anon = MagicMock()
        mock_anon.anonymized_text = "Clean text."

        with (
            patch.object(handler._client, "scan_text", return_value=mock_scan),  # type: ignore[attr-defined]
            patch.object(handler._client, "anonymize", return_value=mock_anon),  # type: ignore[attr-defined]
        ):
            clean_docs, records = handler.process_documents(["Clean text."])

        assert records[0].entity_count == 0
        assert records[0].redacted is False
