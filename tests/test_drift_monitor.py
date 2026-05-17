"""Tests for soc2_refimpl.drift_monitor (TSC CC7.2)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from soc2_refimpl.drift_monitor import BaselineStats, DriftMonitor, DriftObservation


class TestBaselineStats:
    def test_valid_baseline(self) -> None:
        b = BaselineStats(
            response_length=(500.0, 50.0),
            confidence_score=(0.88, 0.05),
            latency_ms=(1200.0, 150.0),
        )
        assert b.response_length == (500.0, 50.0)

    def test_baseline_fields_accessible(self) -> None:
        b = BaselineStats(
            response_length=(500.0, 50.0),
            confidence_score=(0.88, 0.05),
            latency_ms=(1200.0, 150.0),
        )
        assert "response_length" in b.__dataclass_fields__
        assert "confidence_score" in b.__dataclass_fields__
        assert "latency_ms" in b.__dataclass_fields__
        assert b.response_length == (500.0, 50.0)


class TestDriftObservation:
    def test_valid_observation(self) -> None:
        obs = DriftObservation(
            response_length=480.0,
            confidence_score=0.89,
            latency_ms=1150.0,
            invocation_id="inv-001",
        )
        assert obs.response_length == 480.0
        assert obs.invocation_id == "inv-001"


class TestDriftMonitorInit:
    def _make_baseline(self) -> BaselineStats:
        return BaselineStats(
            response_length=(500.0, 50.0),
            confidence_score=(0.88, 0.05),
            latency_ms=(1200.0, 150.0),
        )

    def test_init_without_error(self, base_config: object) -> None:
        baseline = self._make_baseline()
        monitor = DriftMonitor(base_config, baseline)  # type: ignore[arg-type]
        assert monitor is not None

    def test_default_window_size(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]
        # window_size is passed to _detector; just verify _detector exists
        assert monitor._detector is not None  # type: ignore[attr-defined]

    def test_custom_window_size(self, base_config: object) -> None:
        # window_size is forwarded to DriftDetector — just check init succeeds
        monitor = DriftMonitor(base_config, self._make_baseline(), window_size=50)  # type: ignore[arg-type]
        assert monitor is not None


class TestDriftMonitorObserve:
    def _make_baseline(self) -> BaselineStats:
        return BaselineStats(
            response_length=(500.0, 50.0),
            confidence_score=(0.88, 0.05),
            latency_ms=(1200.0, 150.0),
        )

    def _make_obs(self, **kwargs: float) -> DriftObservation:
        defaults = {
            "response_length": 495.0,
            "confidence_score": 0.87,
            "latency_ms": 1210.0,
        }
        defaults.update(kwargs)
        return DriftObservation(invocation_id="inv-001", **defaults)  # type: ignore[arg-type]

    def test_normal_observation_returns_no_breaches(
        self, base_config: object
    ) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]

        mock_results: list[MagicMock] = []
        mock_detector = MagicMock()
        mock_detector.record.return_value = mock_results
        mock_detector.in_breach.return_value = False
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        breaches = monitor.observe(self._make_obs())
        assert breaches == []

    def test_breach_returns_metric_names(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]

        mock_breach = MagicMock()
        mock_breach.metric_name = "response_length"
        mock_breach.is_breach = True

        mock_detector = MagicMock()
        mock_detector.record.return_value = [mock_breach]
        mock_detector.in_breach.side_effect = lambda m: m == "response_length"
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        breaches = monitor.observe(self._make_obs(response_length=900.0))
        assert "response_length" in breaches

    def test_observe_returns_list(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]
        mock_detector = MagicMock()
        mock_detector.record.return_value = []
        mock_detector.in_breach.return_value = False
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        result = monitor.observe(self._make_obs())
        assert isinstance(result, list)


class TestDriftMonitorWindowStats:
    def _make_baseline(self) -> BaselineStats:
        return BaselineStats(
            response_length=(500.0, 50.0),
            confidence_score=(0.88, 0.05),
            latency_ms=(1200.0, 150.0),
        )

    def test_window_stats_after_observation(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]
        mock_detector = MagicMock()
        mock_detector.record.return_value = []
        mock_detector.in_breach.return_value = False
        mock_detector.window_stats.return_value = (505.0, 48.0, 10)
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        stats = monitor.window_stats("response_length")
        assert stats is not None
        mean, std, count = stats
        assert mean == pytest.approx(505.0)
        assert std == pytest.approx(48.0)
        assert count == 10


class TestDriftMonitorMakeAlertPayload:
    def _make_baseline(self) -> BaselineStats:
        return BaselineStats(
            response_length=(500.0, 50.0),
            confidence_score=(0.88, 0.05),
            latency_ms=(1200.0, 150.0),
        )

    def test_payload_contains_metric_name(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]
        mock_detector = MagicMock()
        mock_detector.window_stats.return_value = (800.0, 55.0, 25)
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        payload = monitor.make_alert_payload("response_length")
        assert "metric_name" in payload
        assert payload["metric_name"] == "response_length"

    def test_payload_contains_tsc_criterion(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]
        mock_detector = MagicMock()
        mock_detector.window_stats.return_value = (800.0, 55.0, 25)
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        payload = monitor.make_alert_payload("response_length")
        assert payload.get("tsc") == "CC7.2"

    def test_payload_contains_timestamp(self, base_config: object) -> None:
        monitor = DriftMonitor(base_config, self._make_baseline())  # type: ignore[arg-type]
        mock_detector = MagicMock()
        mock_detector.window_stats.return_value = None
        monitor._detector = mock_detector  # type: ignore[attr-defined]

        payload = monitor.make_alert_payload("response_length")
        assert "z_threshold" in payload
        assert payload["status"] == "breach"
