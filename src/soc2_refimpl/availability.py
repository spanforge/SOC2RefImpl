"""
soc2_refimpl.availability — AI pipeline availability monitoring (TSC A1.2).

Captures p50/p95/p99 latency and uptime metrics for the loan-summary pipeline
and exports them as OpenTelemetry spans via :class:`~spanforge.sdk.observe.SFObserveClient`.

Evidence produced: availability span records (``availability_spans.jsonl``)
cross-referenced with SpanForge span IDs, satisfying A1.2.

The rolling statistics window allows the monitor to report uptime percentage
and latency percentiles for any time period without external dependencies.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from spanforge.sdk.observe import (  # type: ignore[import-untyped, attr-defined, no-untyped-def]
    SFClientConfig,
    SFObserveClient,
)

from soc2_refimpl.config import PipelineConfig

log = logging.getLogger(__name__)

# Number of invocations to retain in the rolling window for percentile calc.
_WINDOW_SIZE = 1000


@dataclass
class _InvocationMetric:
    """Single invocation measurement stored in the rolling window."""

    duration_ms: float
    success: bool
    timestamp: float = field(default_factory=time.monotonic)


@dataclass
class AvailabilityStats:
    """Summary statistics for a period of pipeline observations.

    Attributes
    ----------
    total_invocations:
        Total number of invocations in the window.
    error_count:
        Number of invocations that ended in error.
    uptime_pct:
        Percentage of successful invocations (0–100).
    p50_ms, p95_ms, p99_ms:
        Latency percentiles in milliseconds.
    """

    total_invocations: int
    error_count: int
    uptime_pct: float
    p50_ms: float
    p95_ms: float
    p99_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_invocations": self.total_invocations,
            "error_count": self.error_count,
            "uptime_pct": round(self.uptime_pct, 4),
            "p50_ms": round(self.p50_ms, 2),
            "p95_ms": round(self.p95_ms, 2),
            "p99_ms": round(self.p99_ms, 2),
        }


class AvailabilityMonitor:
    """Records pipeline availability metrics and exports them via OTel (A1.2).

    Parameters
    ----------
    config:
        Pipeline configuration (provides project ID and OTel endpoint).
    window_size:
        Maximum number of invocation measurements retained in the rolling window.
    """

    def __init__(
        self,
        config: PipelineConfig,
        window_size: int = _WINDOW_SIZE,
    ) -> None:
        sf_cfg: SFClientConfig = config.to_sf_client_config()  # type: ignore[assignment]
        self._client = SFObserveClient(sf_cfg)
        self._project_id = config.project_id
        self._otel_endpoint = config.otel_endpoint
        self._window: deque[_InvocationMetric] = deque(maxlen=window_size)
        self._lock = threading.Lock()
        log.debug("AvailabilityMonitor initialised (project=%s)", config.project_id)

    def record_invocation(
        self,
        invocation_id: str,
        duration_ms: float,
        *,
        success: bool,
    ) -> str:
        """Record one pipeline invocation and emit a SpanForge observability span.

        Parameters
        ----------
        invocation_id:
            Unique ID of the invocation (cross-referenced in audit chain).
        duration_ms:
            Wall-clock duration of the invocation in milliseconds.
        success:
            ``True`` if the invocation completed without error.

        Returns
        -------
        str
            SpanForge span ID for cross-referencing with the audit chain.
        """
        with self._lock:
            self._window.append(
                _InvocationMetric(duration_ms=duration_ms, success=success)
            )

        attributes: dict[str, Any] = {
            "invocation_id": invocation_id,
            "duration_ms": duration_ms,
            "success": success,
            "project_id": self._project_id,
            "tsc": "A1.2",
        }

        try:
            span_id: str = self._client.emit_span(
                f"{self._project_id}.invocation",
                attributes=attributes,
            )
        except Exception as exc:
            log.debug("OTel span emit failed (non-fatal): %s", exc)
            span_id = ""

        log.info(
            "Availability [%s]: duration=%.1fms success=%s span_id=%s (A1.2)",
            invocation_id,
            duration_ms,
            success,
            span_id,
        )
        return span_id

    def get_stats(self) -> AvailabilityStats:
        """Return rolling-window availability statistics.

        Returns
        -------
        AvailabilityStats
            Current availability and latency percentile summary.
        """
        with self._lock:
            snapshot = list(self._window)

        if not snapshot:
            return AvailabilityStats(
                total_invocations=0,
                error_count=0,
                uptime_pct=100.0,
                p50_ms=0.0,
                p95_ms=0.0,
                p99_ms=0.0,
            )

        total = len(snapshot)
        errors = sum(1 for m in snapshot if not m.success)
        uptime = (total - errors) / total * 100.0
        durations = sorted(m.duration_ms for m in snapshot)

        def _pct(data: list[float], p: float) -> float:
            idx = min(int(len(data) * p / 100), len(data) - 1)
            return data[idx]

        return AvailabilityStats(
            total_invocations=total,
            error_count=errors,
            uptime_pct=uptime,
            p50_ms=_pct(durations, 50),
            p95_ms=_pct(durations, 95),
            p99_ms=_pct(durations, 99),
        )

    def export_spans(self, spans: list[dict[str, Any]]) -> None:
        """Push a batch of spans to the configured OTel collector."""
        if not self._otel_endpoint:
            log.debug("No OTel endpoint configured; skipping span export")
            return
        try:
            self._client.export_spans(spans)
        except Exception as exc:
            log.warning("OTel span export failed: %s", exc)
