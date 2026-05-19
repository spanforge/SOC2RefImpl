"""
soc2_refimpl.compliance — CEC evidence bundle export (all TSC criteria).

The Compliance Evidence Connector (CEC) aggregates all per-criterion audit
records into a single signed, WORM-archived bundle that can be handed to
auditors.  The bundle includes machine-readable JSONL for every TSC criterion
and a human-readable manifest.

In local mode, :meth:`ComplianceExporter.export_local` writes JSONL files to
``audit_output_dir`` and produces a ``manifest.json``.  When a SpanForge
cloud API key is configured, :meth:`ComplianceExporter.build_cloud_bundle`
calls :class:`~spanforge.sdk.cec.SFCECClient` to generate a signed ZIP.

Evidence produced: ``soc2_bundle.zip`` (cloud) or ``audit_output/`` (local).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from spanforge.sdk.cec import SFCECClient

from soc2_refimpl.audit_chain import AuditChain
from soc2_refimpl.availability import AvailabilityMonitor
from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.models import (
    GateDecision,
    InvocationRecord,
    RedactionRecord,
    SecretScanRecord,
)

log = logging.getLogger(__name__)

_TSC_DESCRIPTIONS = {
    "CC6.1": "Logical access controls — every model invocation traced and signed",
    "CC6.6": "Restriction of access to sensitive data — PII detection and redaction",
    "CC6.8": "Prevention of unauthorized output — secret/credential scan",
    "CC7.2": "System monitoring — behavioural drift detection",
    "CC7.4": "Incident response — human-in-the-loop escalation gate",
    "CC9.2": "Risk monitoring (third parties) — tamper-evident HMAC audit chain",
    "A1.2":  "Availability — AI pipeline uptime and latency metrics",
}


class ComplianceExporter:
    """Generates the SOC 2 evidence bundle from all pipeline audit records.

    Parameters
    ----------
    config:
        Pipeline configuration.
    audit_chain:
        The :class:`~soc2_refimpl.audit_chain.AuditChain` instance used
        throughout the pipeline.
    availability_monitor:
        The :class:`~soc2_refimpl.availability.AvailabilityMonitor` instance.
    """

    def __init__(
        self,
        config: PipelineConfig,
        audit_chain: AuditChain,
        availability_monitor: AvailabilityMonitor,
    ) -> None:
        self._cec: SFCECClient = config.to_sf_factory().cec  # type: ignore[assignment]
        self._config = config
        self._audit_chain = audit_chain
        self._availability = availability_monitor
        self._output_dir = Path(config.audit_output_dir)

        # In-memory collections for local export
        self._invocations: list[InvocationRecord] = []
        self._pii_records: list[RedactionRecord] = []
        self._secret_records: list[SecretScanRecord] = []
        self._gate_decisions: list[GateDecision] = []
        self._drift_alerts: list[dict[str, Any]] = []

        log.debug("ComplianceExporter initialised (project=%s)", config.project_id)

    # ------------------------------------------------------------------
    # Evidence accumulation (called by pipeline on each invocation)
    # ------------------------------------------------------------------

    def add_invocation(self, record: InvocationRecord) -> None:
        """Register an invocation record for CC6.1 evidence."""
        self._invocations.append(record)

    def add_pii_records(self, records: list[RedactionRecord]) -> None:
        """Register PII redaction records for CC6.6 evidence."""
        self._pii_records.extend(records)

    def add_secret_record(self, record: SecretScanRecord) -> None:
        """Register a secret scan result for CC6.8 evidence."""
        self._secret_records.append(record)

    def add_gate_decision(self, decision: GateDecision) -> None:
        """Register a gate decision for CC7.4 evidence."""
        self._gate_decisions.append(decision)

    def add_drift_alert(self, alert: dict[str, Any]) -> None:
        """Register a drift alert for CC7.2 evidence."""
        self._drift_alerts.append(alert)

    # ------------------------------------------------------------------
    # Local export (works without SpanForge cloud)
    # ------------------------------------------------------------------

    def export_local(self) -> dict[str, Path]:
        """Write all evidence records to JSONL files in ``audit_output_dir``.

        Returns
        -------
        dict[str, Path]
            Mapping from artifact name to output path.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}

        def _write(name: str, data: list[Any]) -> None:
            path = self._output_dir / name
            with path.open("w", encoding="utf-8") as fh:
                for item in data:
                    record = item.to_dict() if hasattr(item, "to_dict") else item
                    fh.write(json.dumps(record, default=str) + "\n")
            written[name] = path
            log.info("Exported %d records → %s", len(data), path)

        _write("invocations.jsonl", self._invocations)  # CC6.1
        _write("pii_redaction.jsonl", self._pii_records)  # CC6.6
        _write("secrets_scan.jsonl", self._secret_records)  # CC6.8
        _write("drift_alerts.jsonl", self._drift_alerts)  # CC7.2
        _write("gate_escalations.jsonl", self._gate_decisions)  # CC7.4

        # Export audit chain (CC9.2)
        chain_path = self._audit_chain.export_jsonl()
        written["audit_chain.jsonl"] = chain_path

        # Availability stats (A1.2)
        stats = self._availability.get_stats()
        avail_path = self._output_dir / "availability_stats.json"
        avail_path.write_text(json.dumps(stats.to_dict(), indent=2), encoding="utf-8")
        written["availability_stats.json"] = avail_path

        # Manifest
        manifest = self._build_manifest(written)
        manifest_path = self._output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        written["manifest.json"] = manifest_path

        log.info(
            "Local evidence bundle written to %s (%d artifacts)",
            self._output_dir,
            len(written),
        )
        return written

    # ------------------------------------------------------------------
    # Cloud bundle (requires SpanForge API key)
    # ------------------------------------------------------------------

    def build_cloud_bundle(
        self,
        period_start: str,
        period_end: str,
    ) -> str | None:
        """Build a signed CEC evidence bundle via the SpanForge cloud API.

        Parameters
        ----------
        period_start:
            ISO-8601 date (e.g. ``"2026-01-01"``).
        period_end:
            ISO-8601 date (e.g. ``"2026-03-31"``).

        Returns
        -------
        str | None
            Bundle ID returned by the CEC API, or ``None`` if unavailable.
        """
        if not self._config.api_key:
            log.info(
                "No SpanForge API key configured — skipping cloud bundle generation. "
                "Use export_local() instead."
            )
            return None

        try:
            result = self._cec.build_bundle(
                project_id=self._config.project_id,
                date_range=(period_start, period_end),
                frameworks=["SOC2"],
            )
            bundle_id: str = result.bundle_id if hasattr(result, "bundle_id") else ""
            log.info("CEC cloud bundle created: bundle_id=%s", bundle_id)
            return bundle_id
        except Exception as exc:
            log.error("CEC cloud bundle failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_manifest(self, artifacts: dict[str, Path]) -> dict[str, Any]:
        """Build the ``manifest.json`` summarising all artifacts and TSC coverage."""
        avail_stats = self._availability.get_stats()
        escalated = sum(1 for d in self._gate_decisions if d.routed_to_human)
        pii_total = sum(r.entity_count for r in self._pii_records)
        secrets_detected = sum(1 for s in self._secret_records if s.detected)

        return {
            "bundle_id": f"soc2-local-{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}",
            "service": self._config.project_id,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "spans_total": len(self._invocations),
            "tsc_mapping": {
                "CC6.1": f"{len(self._invocations)} traced invocations",
                "CC6.6": (
                    f"{pii_total} PII entities redacted across"
                    f" {len(self._pii_records)} documents"
                ),
                "CC6.8": f"{secrets_detected} secrets detected in output",
                "CC7.2": f"{len(self._drift_alerts)} drift alerts",
                "CC7.4": f"{escalated} escalations to human review",
                "CC9.2": "HMAC chain — verify with audit_chain.verify()",
                "A1.2": (
                    f"{avail_stats.uptime_pct:.2f}% uptime;"
                    f" p99 latency {avail_stats.p99_ms:.0f}ms"
                ),
            },
            "artifacts": {name: str(path) for name, path in artifacts.items()},
            "tsc_descriptions": _TSC_DESCRIPTIONS,
        }
