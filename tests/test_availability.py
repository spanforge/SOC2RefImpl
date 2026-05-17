"""Tests for soc2_refimpl.availability (TSC A1.2)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from soc2_refimpl.availability import AvailabilityMonitor, AvailabilityStats


class TestAvailabilityStats:
    def test_all_fields_accessible(self) -> None:
        stats = AvailabilityStats(
            total_invocations=100,
            error_count=5,
            uptime_pct=95.0,
            p50_ms=1000.0,
            p95_ms=2500.0,
            p99_ms=4000.0,
        )
        assert stats.total_invocations == 100
        assert stats.error_count == 5
        assert stats.uptime_pct == pytest.approx(95.0)

    def test_to_dict(self) -> None:
        stats = AvailabilityStats(
            total_invocations=50,
            error_count=2,
            uptime_pct=96.0,
            p50_ms=900.0,
            p95_ms=2000.0,
            p99_ms=3500.0,
        )
        d = stats.to_dict()
        assert d["total_invocations"] == 50
        assert d["error_count"] == 2
        assert d["uptime_pct"] == pytest.approx(96.0)
        assert d["p50_ms"] == pytest.approx(900.0)
        assert d["p95_ms"] == pytest.approx(2000.0)
        assert d["p99_ms"] == pytest.approx(3500.0)


class TestAvailabilityMonitorInit:
    def test_initialises_without_error(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        assert monitor is not None

    def test_default_window_size(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        assert monitor._window.maxlen == 1000  # type: ignore[attr-defined]

    def test_custom_window_size(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config, window_size=500)  # type: ignore[arg-type]
        assert monitor._window.maxlen == 500  # type: ignore[attr-defined]

    def test_initial_counts_are_zero(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        stats = monitor.get_stats()
        assert stats.total_invocations == 0
        assert stats.error_count == 0


class TestAvailabilityMonitorRecordInvocation:
    def test_record_success_increments_total(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        with patch.object(monitor._client, "emit_span", return_value="span-001"):  # type: ignore[attr-defined]
            monitor.record_invocation("inv-001", 1200.0, success=True)
        stats = monitor.get_stats()
        assert stats.total_invocations == 1

    def test_record_failure_increments_error_count(
        self, base_config: object
    ) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        with patch.object(monitor._client, "emit_span", return_value="span-001"):  # type: ignore[attr-defined]
            monitor.record_invocation("inv-001", 1200.0, success=False)
        stats = monitor.get_stats()
        assert stats.error_count == 1

    def test_multiple_records_accumulate(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        with patch.object(monitor._client, "emit_span", return_value="span-001"):  # type: ignore[attr-defined]
            for i in range(5):
                monitor.record_invocation(f"inv-{i}", 1000.0 + i * 100, success=True)
        stats = monitor.get_stats()
        assert stats.total_invocations == 5

    def test_returns_span_id_string(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        with patch.object(
            monitor._client, "emit_span", return_value="span-abc"  # type: ignore[attr-defined]
        ):
            span_id = monitor.record_invocation("inv-001", 1200.0, success=True)
        assert span_id == "span-abc"


class TestAvailabilityMonitorGetStats:
    def test_uptime_100_when_all_success(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        with patch.object(monitor._client, "emit_span", return_value="s"):  # type: ignore[attr-defined]
            for i in range(10):
                monitor.record_invocation(f"inv-{i}", 1000.0, success=True)
        stats = monitor.get_stats()
        assert stats.uptime_pct == pytest.approx(100.0)

    def test_uptime_90_when_one_in_ten_fails(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        with patch.object(monitor._client, "emit_span", return_value="s"):  # type: ignore[attr-defined]
            for i in range(9):
                monitor.record_invocation(f"inv-{i}", 1000.0, success=True)
            monitor.record_invocation("inv-fail", 1000.0, success=False)
        stats = monitor.get_stats()
        assert stats.uptime_pct == pytest.approx(90.0)

    def test_uptime_100_when_no_invocations(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        stats = monitor.get_stats()
        assert stats.uptime_pct == pytest.approx(100.0)

    def test_percentiles_computed(self, base_config: object) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        durations = [float(i * 100) for i in range(1, 101)]  # 100–10000 ms

        with patch.object(monitor._client, "emit_span", return_value="s"):  # type: ignore[attr-defined]
            for i, d in enumerate(durations):
                monitor.record_invocation(f"inv-{i}", d, success=True)

        stats = monitor.get_stats()
        assert stats.p50_ms > 0
        assert stats.p95_ms >= stats.p50_ms
        assert stats.p99_ms >= stats.p95_ms

    def test_stats_when_zero_invocations_returns_zero_percentiles(
        self, base_config: object
    ) -> None:
        monitor = AvailabilityMonitor(base_config)  # type: ignore[arg-type]
        stats = monitor.get_stats()
        assert stats.p50_ms == 0.0
        assert stats.p95_ms == 0.0
        assert stats.p99_ms == 0.0
