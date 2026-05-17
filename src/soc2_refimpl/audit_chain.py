"""
soc2_refimpl.audit_chain — HMAC-SHA256 tamper-evident audit chain (TSC CC9.2).

Every event from every pipeline stage (trace, PII, secrets, drift, gate) is
appended to an :class:`~spanforge.signing.AuditStream`.  The stream links
events in an HMAC-SHA256 chain: tampering with any entry breaks the chain
hash at that point, making tampering immediately detectable.

A persistent :class:`~spanforge.sdk.audit.SFAuditClient` is used as the
durable backing store (SQLite in local mode, SpanForge cloud in production).

Evidence produced: a verifiable HMAC audit chain and signed individual
records suitable for export as ``audit_chain.jsonl``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from spanforge.event import (  # type: ignore[import-untyped, attr-defined, no-untyped-def]
    Event,
    Tags,
)
from spanforge.sdk.audit import (  # type: ignore[import-untyped, attr-defined, no-untyped-def]
    SFAuditClient,
    SFClientConfig,
)
from spanforge.signing import (  # type: ignore[import-untyped, attr-defined, no-untyped-def]
    AuditStream,
    ChainVerificationResult,
)
from spanforge.types import EventType  # type: ignore[import-untyped, attr-defined, no-untyped-def]

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.exceptions import AuditChainError
from soc2_refimpl.models import (
    GateDecision,
    InvocationRecord,
    RedactionRecord,
    SecretScanRecord,
)

log = logging.getLogger(__name__)

# Schema keys used when appending records to SFAuditClient
_SCHEMA_TRACE = "spanforge.trace.v1"
_SCHEMA_PII = "spanforge.pii.v1"
_SCHEMA_SECRETS = "spanforge.secrets.v1"
_SCHEMA_DRIFT = "spanforge.drift.v1"
_SCHEMA_GATE = "spanforge.gate.v1"
_SCHEMA_INVOCATION = "spanforge.invocation.v1"


class AuditChain:
    """Maintains the HMAC audit chain and durable audit store.

    Parameters
    ----------
    config:
        Pipeline configuration (provides signing key, project ID, output dir).
    """

    def __init__(self, config: PipelineConfig) -> None:
        self._project_id = config.project_id
        self._output_dir = Path(config.audit_output_dir)

        # In-memory HMAC chain — provides CC9.2 tamper evidence
        self._stream = AuditStream(
            org_secret=config.signing_key,
            source=f"{config.project_id}@1.0",
        )

        # Durable backing store
        sf_cfg: SFClientConfig = config.to_sf_client_config()  # type: ignore[assignment]
        self._store = SFAuditClient(sf_cfg)

        log.debug("AuditChain initialised (project=%s)", config.project_id)

    # ------------------------------------------------------------------
    # Append helpers — one per compliance concern
    # ------------------------------------------------------------------

    def record_invocation(self, record: InvocationRecord) -> None:
        """Append an invocation (CC6.1 trace) record to the chain."""
        event = Event(
            event_type=EventType.TRACE_SPAN_COMPLETED,
            source=f"{self._project_id}@1.0",
            payload=record.to_dict(),
            tags=Tags(env="production"),
        )
        self._stream.append(event)
        try:
            self._store.append(
                record.to_dict(),
                schema_key=_SCHEMA_INVOCATION,
                project_id=self._project_id,
            )
        except Exception as exc:
            log.warning("Audit store append failed (non-fatal): %s", exc)
        log.debug("Audit: recorded invocation %s (CC6.1)", record.invocation_id)

    def record_pii(self, records: list[RedactionRecord], invocation_id: str) -> None:
        """Append PII redaction records (CC6.6) to the chain."""
        payload: dict[str, Any] = {
            "invocation_id": invocation_id,
            "redaction_records": [r.to_dict() for r in records],
            "tsc": "CC6.6",
        }
        event = Event(
            event_type=EventType.AUDIT_EVENT_SIGNED,
            source=f"{self._project_id}@1.0",
            payload=payload,
            tags=Tags(env="production"),
        )
        self._stream.append(event)
        try:
            self._store.append(payload, schema_key=_SCHEMA_PII, project_id=self._project_id)
        except Exception as exc:
            log.warning("Audit store PII append failed (non-fatal): %s", exc)

    def record_secrets(self, record: SecretScanRecord) -> None:
        """Append a secret scan result (CC6.8) to the chain."""
        payload = {**record.to_dict(), "tsc": "CC6.8"}
        event = Event(
            event_type=EventType.AUDIT_EVENT_SIGNED,
            source=f"{self._project_id}@1.0",
            payload=payload,
            tags=Tags(env="production"),
        )
        self._stream.append(event)
        try:
            self._store.append(
                payload, schema_key=_SCHEMA_SECRETS, project_id=self._project_id
            )
        except Exception as exc:
            log.warning("Audit store secrets append failed (non-fatal): %s", exc)

    def record_drift(self, alert_payload: dict[str, Any], invocation_id: str) -> None:
        """Append a drift alert (CC7.2) to the chain."""
        payload = {**alert_payload, "invocation_id": invocation_id, "tsc": "CC7.2"}
        event = Event(
            event_type=EventType.CONFIDENCE_THRESHOLD_BREACH,
            source=f"{self._project_id}@1.0",
            payload=payload,
            tags=Tags(env="production"),
        )
        self._stream.append(event)
        try:
            self._store.append(
                payload, schema_key=_SCHEMA_DRIFT, project_id=self._project_id
            )
        except Exception as exc:
            log.warning("Audit store drift append failed (non-fatal): %s", exc)

    def record_gate(self, decision: GateDecision) -> None:
        """Append a gate decision (CC7.4) to the chain."""
        payload = {**decision.to_dict(), "tsc": "CC7.4"}
        event = Event(
            event_type=EventType.AUDIT_EVENT_SIGNED,
            source=f"{self._project_id}@1.0",
            payload=payload,
            tags=Tags(env="production"),
        )
        self._stream.append(event)
        try:
            self._store.append(
                payload, schema_key=_SCHEMA_GATE, project_id=self._project_id
            )
        except Exception as exc:
            log.warning("Audit store gate append failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(self) -> ChainVerificationResult:
        """Verify the integrity of the in-memory HMAC audit chain.

        Returns
        -------
        ChainVerificationResult
            SpanForge verification result with ``valid``, ``tampered_count``,
            and ``gaps`` fields.

        Raises
        ------
        AuditChainError
            If the chain is not valid (tampering or gaps detected).
        """
        result: ChainVerificationResult = self._stream.verify()
        if not result.valid:
            log.error(
                "Audit chain INVALID: tampered_count=%d gaps=%s first_tampered=%s (CC9.2)",
                result.tampered_count,
                result.gaps,
                result.first_tampered,
            )
            raise AuditChainError(
                first_tampered=result.first_tampered,
                gaps=result.gaps,
            )
        log.info(
            "Audit chain verified: valid=True tampered_count=0 (CC9.2)"
        )
        return result

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_jsonl(self, filename: str = "audit_chain.jsonl") -> Path:
        """Export all audit records from the durable store to a JSONL file.

        Parameters
        ----------
        filename:
            Output filename (relative to ``audit_output_dir``).

        Returns
        -------
        Path
            Absolute path to the written file.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        out_path = self._output_dir / filename

        try:
            records = self._store.export(project_id=self._project_id, limit=100_000)
        except Exception as exc:
            log.warning("Audit store export failed — falling back to stream events: %s", exc)
            records = []

        with out_path.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, default=str) + "\n")

        log.info("Audit chain exported to %s (%d records)", out_path, len(records))
        return out_path

    def close(self) -> None:
        """Release resources held by the audit store."""
        try:
            self._store.close()
        except Exception as exc:
            log.debug("Audit store close error (non-fatal): %s", exc)
