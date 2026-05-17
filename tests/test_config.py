"""Tests for soc2_refimpl.config (PipelineConfig)."""

from __future__ import annotations

import pytest

from soc2_refimpl.config import _MIN_SIGNING_KEY_LEN, PipelineConfig, _make_signing_key

TEST_KEY = "z" * 64


class TestMakeSigningKey:
    def test_returns_string_of_correct_length(self) -> None:
        key = _make_signing_key()
        # token_hex(32) → 64 chars
        assert len(key) == 64

    def test_returns_hex_chars(self) -> None:
        key = _make_signing_key()
        assert all(c in "0123456789abcdef" for c in key)

    def test_unique_each_call(self) -> None:
        keys = {_make_signing_key() for _ in range(20)}
        assert len(keys) == 20  # all unique


class TestPipelineConfigDefaults:
    def test_default_project_id(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY)
        assert cfg.project_id == "meridian-loan-summary"

    def test_default_confidence_threshold(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY)
        assert cfg.confidence_threshold == 0.82

    def test_default_drift_z_threshold(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY)
        assert cfg.drift_z_threshold == 3.0

    def test_default_local_fallback_true(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY)
        assert cfg.local_fallback is True

    def test_default_tsc_criteria_all_present(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY)
        expected = {"CC6.1", "CC6.6", "CC6.8", "CC7.2", "CC7.4", "CC9.2", "A1.2"}
        assert set(cfg.tsc_criteria) == expected

    def test_auto_generated_signing_key_valid_length(self) -> None:
        cfg = PipelineConfig()
        assert len(cfg.signing_key) >= _MIN_SIGNING_KEY_LEN


class TestPipelineConfigValidation:
    def test_short_signing_key_raises(self) -> None:
        with pytest.raises(ValueError, match="signing_key must be at least"):
            PipelineConfig(signing_key="short")

    def test_confidence_threshold_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence_threshold"):
            PipelineConfig(signing_key=TEST_KEY, confidence_threshold=0.0)

    def test_confidence_threshold_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence_threshold"):
            PipelineConfig(signing_key=TEST_KEY, confidence_threshold=1.1)

    def test_confidence_threshold_one_is_valid(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY, confidence_threshold=1.0)
        assert cfg.confidence_threshold == 1.0

    def test_drift_z_threshold_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="drift_z_threshold"):
            PipelineConfig(signing_key=TEST_KEY, drift_z_threshold=0.0)

    def test_drift_z_threshold_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="drift_z_threshold"):
            PipelineConfig(signing_key=TEST_KEY, drift_z_threshold=-1.0)


class TestPipelineConfigFromEnv:
    def test_from_env_uses_defaults_when_no_vars(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SPANFORGE_API_KEY", raising=False)
        monkeypatch.delenv("SPANFORGE_SIGNING_KEY", raising=False)
        monkeypatch.delenv("CONFIDENCE_THRESHOLD", raising=False)
        monkeypatch.delenv("DRIFT_Z_THRESHOLD", raising=False)
        cfg = PipelineConfig.from_env()
        assert cfg.local_fallback is True
        assert cfg.confidence_threshold == 0.82
        assert cfg.drift_z_threshold == 3.0
        assert len(cfg.signing_key) >= _MIN_SIGNING_KEY_LEN

    def test_from_env_reads_project_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SPANFORGE_PROJECT_ID", "my-project")
        monkeypatch.delenv("SPANFORGE_SIGNING_KEY", raising=False)
        cfg = PipelineConfig.from_env()
        assert cfg.project_id == "my-project"

    def test_from_env_reads_confidence_threshold(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CONFIDENCE_THRESHOLD", "0.75")
        monkeypatch.delenv("SPANFORGE_SIGNING_KEY", raising=False)
        cfg = PipelineConfig.from_env()
        assert cfg.confidence_threshold == 0.75

    def test_from_env_reads_signing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = "b" * 64
        monkeypatch.setenv("SPANFORGE_SIGNING_KEY", key)
        cfg = PipelineConfig.from_env()
        assert cfg.signing_key == key

    def test_from_env_disables_local_fallback_when_api_key_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SPANFORGE_API_KEY", "sf-test-key-xyz")
        monkeypatch.delenv("SPANFORGE_SIGNING_KEY", raising=False)
        cfg = PipelineConfig.from_env()
        assert cfg.local_fallback is False

    def test_from_env_invalid_confidence_uses_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CONFIDENCE_THRESHOLD", "not-a-number")
        monkeypatch.delenv("SPANFORGE_SIGNING_KEY", raising=False)
        cfg = PipelineConfig.from_env()
        assert cfg.confidence_threshold == 0.82

    def test_from_env_false_local_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SPANFORGE_LOCAL_FALLBACK", "false")
        monkeypatch.setenv("SPANFORGE_SIGNING_KEY", TEST_KEY)
        cfg = PipelineConfig.from_env()
        assert cfg.local_fallback is False

    def test_from_env_zero_local_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SPANFORGE_LOCAL_FALLBACK", "0")
        monkeypatch.setenv("SPANFORGE_SIGNING_KEY", TEST_KEY)
        cfg = PipelineConfig.from_env()
        assert cfg.local_fallback is False


class TestToSFClientConfig:
    def test_returns_sf_client_config_object(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY)
        sf_cfg = cfg.to_sf_client_config()
        assert sf_cfg is not None
        assert hasattr(sf_cfg, "local_fallback_enabled")

    def test_local_fallback_set_correctly(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY, local_fallback=True)
        sf_cfg = cfg.to_sf_client_config()
        assert sf_cfg.local_fallback_enabled is True

    def test_project_id_passed_through(self) -> None:
        cfg = PipelineConfig(signing_key=TEST_KEY, project_id="my-svc")
        sf_cfg = cfg.to_sf_client_config()
        assert sf_cfg.project_id == "my-svc"
