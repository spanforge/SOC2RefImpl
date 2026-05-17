"""
soc2_refimpl.pii_handler — PII detection and redaction (TSC CC6.6).

Implements the PII scanning and redaction step of the pipeline using
``SFPIIClient``.  Every document chunk is scanned before being passed to
the LLM; a :class:`~soc2_refimpl.models.RedactionRecord` is produced for
each chunk as evidence of CC6.6 compliance.

Critical PII entity types (SSN, ACCOUNT_NUMBER) raise
:class:`~soc2_refimpl.exceptions.PIIBlockedError` to halt processing rather
than risk passing unredacted financial identifiers to the model.
"""

from __future__ import annotations

import hashlib
import logging

from spanforge.sdk.pii import (  # type: ignore[import-untyped, attr-defined, no-untyped-def]
    SFClientConfig,
    SFPIIClient,
)

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.exceptions import PIIBlockedError
from soc2_refimpl.models import RedactionRecord, utc_now_iso

log = logging.getLogger(__name__)

# Entity types that are so sensitive that processing must halt if they appear
# unredacted in a document.
_CRITICAL_ENTITY_TYPES: frozenset[str] = frozenset({"SSN", "ACCOUNT_NUMBER", "CREDIT_CARD"})

# Entity types to scan for (superset of document spec)
_SCAN_ENTITIES: list[str] = [
    "SSN",
    "DOB",
    "ACCOUNT_NUMBER",
    "INCOME",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "PERSON",
]


def _sha256(text: str) -> str:
    """Return the hex SHA-256 digest of *text* (for fingerprinting originals)."""
    return hashlib.sha256(text.encode()).hexdigest()


class PIIHandler:
    """Detects and redacts PII from document chunks before LLM ingestion.

    Parameters
    ----------
    config:
        Pipeline configuration used to construct the ``SFPIIClient``.
    """

    def __init__(self, config: PipelineConfig) -> None:
        sf_cfg: SFClientConfig = config.to_sf_client_config()  # type: ignore[assignment]
        self._client = SFPIIClient(sf_cfg)
        log.debug("PIIHandler initialised (local_fallback=%s)", config.local_fallback)

    def process_documents(
        self,
        documents: list[str],
    ) -> tuple[list[str], list[RedactionRecord]]:
        """Scan and redact PII from each document.

        Parameters
        ----------
        documents:
            Raw document strings (e.g. loan application text, policy excerpts).

        Returns
        -------
        clean_docs:
            Documents with PII replaced by typed placeholders.
        records:
            One :class:`~soc2_refimpl.models.RedactionRecord` per document,
            suitable for inclusion in the audit bundle.

        Raises
        ------
        PIIBlockedError
            If any document contains critical PII (SSN, ACCOUNT_NUMBER) that
            cannot be safely redacted before passing to the LLM.
        """
        clean_docs: list[str] = []
        records: list[RedactionRecord] = []

        for idx, doc in enumerate(documents):
            pre_hash = _sha256(doc)
            scan_result = self._client.scan_text(doc, language="en", score_threshold=0.5)

            # SpanForge SDK uses .type (local) or .entity_type (cloud) — handle both
            detected_types = (
                [
                    (getattr(e, "entity_type", None) or getattr(e, "type", "")).upper()
                    for e in scan_result.entities
                ]
                if scan_result.entities
                else []
            )

            # Check for critical PII that must block processing
            critical_found = [t for t in detected_types if t in _CRITICAL_ENTITY_TYPES]
            if critical_found:
                log.warning(
                    "Critical PII detected in document[%d]: %s — halting (CC6.6)",
                    idx,
                    critical_found,
                )
                raise PIIBlockedError(critical_found)

            # Anonymize: replace PII with typed placeholders like <SSN>, <EMAIL_ADDRESS>
            # SpanForge SDK uses .text (local) or .anonymized_text (cloud) — handle both
            anon_result = self._client.anonymize(doc)
            clean_text = (
                anon_result.anonymized_text
                if hasattr(anon_result, "anonymized_text")
                else getattr(anon_result, "text", doc)
            )

            record = RedactionRecord(
                document_index=idx,
                entity_types_detected=detected_types,
                entity_count=len(scan_result.entities) if scan_result.entities else 0,
                redacted=bool(detected_types),
                redacted_at=utc_now_iso(),
                pre_hash=pre_hash,
            )

            clean_docs.append(clean_text)
            records.append(record)

            log.info(
                "Document[%d]: %d PII entities detected (%s) — redacted=%s (CC6.6)",
                idx,
                record.entity_count,
                detected_types,
                record.redacted,
            )

        return clean_docs, records
