"""Tests for soc2_refimpl.secrets_scanner (TSC CC6.8)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from soc2_refimpl.exceptions import SecretDetectedError
from soc2_refimpl.models import SecretScanRecord
from soc2_refimpl.secrets_scanner import _REDACTION_TOKEN, SecretsScanner


class TestSecretsScannerInit:
    def test_initialises_without_error(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        assert scanner is not None

    def test_default_threshold(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        assert scanner._threshold == 0.75  # type: ignore[attr-defined]

    def test_custom_threshold(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config, confidence_threshold=0.90)  # type: ignore[arg-type]
        assert scanner._threshold == 0.90  # type: ignore[attr-defined]

    def test_default_block_on_detection_is_false(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        assert scanner._block_on_detection is False  # type: ignore[attr-defined]


class TestSecretsScannerScan:
    def _make_clean_result(self) -> MagicMock:
        result = MagicMock()
        result.detected = False
        result.secret_types = []
        result.auto_blocked = False
        result.redacted_text = "clean text"
        return result

    def _make_detected_result(self, types: list[str] | None = None) -> MagicMock:
        result = MagicMock()
        result.detected = True
        result.secret_types = types or ["API_KEY"]
        result.auto_blocked = True
        result.redacted_text = "[REDACTED:SECRET]"
        return result

    def test_clean_text_returns_original(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(scanner._client, "scan", return_value=self._make_clean_result()):  # type: ignore[attr-defined]
            output, record = scanner.scan("inv-001", "clean text")
        assert output == "clean text"

    def test_clean_text_record_detected_false(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(scanner._client, "scan", return_value=self._make_clean_result()):  # type: ignore[attr-defined]
            _, record = scanner.scan("inv-001", "clean text")
        assert record.detected is False
        assert record.secret_types == []

    def test_detected_secret_returns_redacted(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(
            scanner._client, "scan", return_value=self._make_detected_result()  # type: ignore[attr-defined]
        ):
            output, _ = scanner.scan("inv-002", "sk-real-secret-key")
        assert "sk-real-secret-key" not in output

    def test_detected_secret_record_has_types(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(
            scanner._client,  # type: ignore[attr-defined]
            "scan",
            return_value=self._make_detected_result(["API_KEY", "BEARER_TOKEN"]),
        ):
            _, record = scanner.scan("inv-003", "sk-abc123")
        assert "API_KEY" in record.secret_types
        assert "BEARER_TOKEN" in record.secret_types

    def test_record_type_is_secret_scan_record(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(scanner._client, "scan", return_value=self._make_clean_result()):  # type: ignore[attr-defined]
            _, record = scanner.scan("inv-004", "text")
        assert isinstance(record, SecretScanRecord)

    def test_invocation_id_in_record(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(scanner._client, "scan", return_value=self._make_clean_result()):  # type: ignore[attr-defined]
            _, record = scanner.scan("my-unique-id-42", "text")
        assert record.invocation_id == "my-unique-id-42"

    def test_scanned_at_is_set(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        with patch.object(scanner._client, "scan", return_value=self._make_clean_result()):  # type: ignore[attr-defined]
            _, record = scanner.scan("inv-005", "text")
        assert record.scanned_at != ""

    def test_block_on_detection_raises_secret_detected_error(
        self, base_config: object
    ) -> None:
        scanner = SecretsScanner(base_config, block_on_detection=True)  # type: ignore[arg-type]
        with patch.object(
            scanner._client, "scan", return_value=self._make_detected_result()  # type: ignore[attr-defined]
        ):
            with pytest.raises(SecretDetectedError) as exc_info:
                scanner.scan("inv-006", "secret here")
        assert exc_info.value.tsc_criterion == "CC6.8"

    def test_no_block_does_not_raise(self, base_config: object) -> None:
        scanner = SecretsScanner(base_config, block_on_detection=False)  # type: ignore[arg-type]
        with patch.object(
            scanner._client, "scan", return_value=self._make_detected_result()  # type: ignore[attr-defined]
        ):
            output, record = scanner.scan("inv-007", "secret here")
        # Should not raise; output should be redacted
        assert record.detected is True

    def test_fallback_redaction_token_when_no_redacted_text(
        self, base_config: object
    ) -> None:
        """If SFSecretsClient provides no redacted_text, use our fallback token."""
        scanner = SecretsScanner(base_config)  # type: ignore[arg-type]
        result = MagicMock()
        result.detected = True
        result.secret_types = ["AWS_SECRET"]
        result.auto_blocked = False
        result.redacted_text = None  # no redacted text provided

        with patch.object(scanner._client, "scan", return_value=result):  # type: ignore[attr-defined]
            output, _ = scanner.scan("inv-008", "aws_secret_key=abc123")
        assert output == _REDACTION_TOKEN
