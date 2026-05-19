"""
soc2_refimpl.secrets_scanner — secret/credential leak detection (TSC CC6.8).

Scans LLM output for API keys, bearer tokens, AWS secrets, and other
credentials that should never appear in a model response.  When a secret
is detected the output is redacted and an alert event is raised.

Evidence produced: one :class:`~soc2_refimpl.models.SecretScanRecord` per
invocation, included verbatim in the CC6.8 section of the audit bundle.
"""

from __future__ import annotations

import logging

from spanforge.sdk.secrets import SFSecretsClient

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.exceptions import SecretDetectedError
from soc2_refimpl.models import SecretScanRecord, utc_now_iso

log = logging.getLogger(__name__)

# Replacement token used when a secret is redacted from the output.
_REDACTION_TOKEN = "[REDACTED:SECRET]"  # nosec B105 — not a real credential

# Default confidence threshold for secret detection.
_DEFAULT_CONFIDENCE = 0.75


class SecretsScanner:
    """Scans LLM output text for secrets and credentials.

    Parameters
    ----------
    config:
        Pipeline configuration used to construct the ``SFSecretsClient``.
    confidence_threshold:
        Minimum confidence score above which a pattern match is treated as a
        detected secret.  Defaults to 0.75.
    block_on_detection:
        When ``True`` (default), raise :class:`~soc2_refimpl.exceptions.SecretDetectedError`
        after redacting.  Set to ``False`` to redact silently (not recommended
        in production).
    """

    def __init__(
        self,
        config: PipelineConfig,
        confidence_threshold: float = _DEFAULT_CONFIDENCE,
        *,
        block_on_detection: bool = False,
    ) -> None:
        self._client: SFSecretsClient = config.to_sf_factory().secrets  # type: ignore[assignment]
        self._threshold = confidence_threshold
        self._block_on_detection = block_on_detection
        log.debug(
            "SecretsScanner initialised (threshold=%.2f, block=%s)",
            confidence_threshold,
            block_on_detection,
        )

    def scan(
        self,
        invocation_id: str,
        text: str,
    ) -> tuple[str, SecretScanRecord]:
        """Scan *text* for secrets and return the (possibly redacted) output.

        Parameters
        ----------
        invocation_id:
            Unique ID of the current pipeline invocation for cross-referencing.
        text:
            Raw LLM output text to scan.

        Returns
        -------
        output_text:
            Original text if no secrets detected; otherwise the redacted version.
        record:
            :class:`~soc2_refimpl.models.SecretScanRecord` for the audit bundle.

        Raises
        ------
        SecretDetectedError
            If ``block_on_detection=True`` and one or more secrets are found.
        """
        result = self._client.scan(text, confidence_threshold=self._threshold)

        output_text = text
        if result.detected:
            log.warning(
                "Secret(s) detected in LLM output for invocation %s: %s — redacting (CC6.8)",
                invocation_id,
                result.secret_types,
            )
            # Use the client-provided redacted text if available, else substitute
            output_text = result.redacted_text if result.redacted_text else _REDACTION_TOKEN

        record = SecretScanRecord(
            invocation_id=invocation_id,
            detected=result.detected,
            secret_types=list(result.secret_types),
            auto_blocked=result.auto_blocked,
            scanned_at=utc_now_iso(),
        )

        log.info(
            "Secrets scan [%s]: detected=%s types=%s (CC6.8)",
            invocation_id,
            result.detected,
            list(result.secret_types),
        )

        if result.detected and self._block_on_detection:
            raise SecretDetectedError(list(result.secret_types))

        return output_text, record
