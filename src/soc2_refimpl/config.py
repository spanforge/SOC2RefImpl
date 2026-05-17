"""
soc2_refimpl.config — configuration factory and environment-variable loading.

All runtime knobs are exposed as environment variables following the
12-factor app pattern.  Defaults are safe for local / CI use without any
SpanForge cloud account.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Load .env on import (no-op if file doesn't exist)
load_dotenv()

log = logging.getLogger(__name__)

# Minimum acceptable signing-key length (bytes) for HMAC-SHA256 security.
_MIN_SIGNING_KEY_LEN = 32


def _env(key: str, default: str = "") -> str:
    """Return stripped environment variable value or *default*."""
    return os.environ.get(key, default).strip()


def _env_float(key: str, default: float) -> float:
    """Return environment variable parsed as float or *default*."""
    raw = _env(key)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        log.warning("Invalid float for %s=%r — using default %s", key, raw, default)
        return default


def _make_signing_key() -> str:
    """Generate a cryptographically secure random signing key."""
    return secrets.token_hex(32)  # 64-char hex → 256 bits


@dataclass
class PipelineConfig:
    """Centralised configuration for the SOC 2 reference pipeline.

    Attributes
    ----------
    api_key:
        SpanForge cloud API key.  Leave empty to use local fallback mode.
    endpoint:
        SpanForge cloud endpoint URL.  Unused in local mode.
    project_id:
        Logical identifier for this pipeline (used in audit records).
    signing_key:
        HMAC-SHA256 key for the CC9.2 audit chain.  Auto-generated when
        not provided; **must be persisted** across restarts in production
        so the chain can be continuously verified.
    local_fallback:
        When ``True`` (default), all SpanForge clients operate against
        local in-memory / SQLite storage instead of the cloud API.
    otel_endpoint:
        OTel collector endpoint for A1.2 availability-metrics export.
    confidence_threshold:
        Gate confidence threshold for CC7.4; responses below this value
        are routed to the human review queue.
    drift_z_threshold:
        Z-score threshold at which a behavioural metric is considered
        in drift breach (CC7.2).
    audit_output_dir:
        Directory for local JSONL audit output when running in local mode.
    model:
        LLM model identifier recorded in audit spans.
    escalation_queue:
        Queue name for HITL escalations (CC7.4).
    tsc_criteria:
        List of TSC criterion codes satisfied by this pipeline.
    """

    api_key: str = ""
    endpoint: str = ""
    project_id: str = "meridian-loan-summary"
    signing_key: str = field(default_factory=_make_signing_key)
    local_fallback: bool = True
    otel_endpoint: str = ""
    confidence_threshold: float = 0.82
    drift_z_threshold: float = 3.0
    audit_output_dir: str = "./audit_output"
    model: str = "gpt-4o"
    escalation_queue: str = "underwriter-review"
    tsc_criteria: list[str] = field(
        default_factory=lambda: ["CC6.1", "CC6.6", "CC6.8", "CC7.2", "CC7.4", "CC9.2", "A1.2"]
    )

    def __post_init__(self) -> None:
        if len(self.signing_key) < _MIN_SIGNING_KEY_LEN:
            raise ValueError(
                f"signing_key must be at least {_MIN_SIGNING_KEY_LEN} characters long. "
                "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        if not (0.0 < self.confidence_threshold <= 1.0):
            raise ValueError(
                f"confidence_threshold must be in (0, 1], got {self.confidence_threshold}"
            )
        if self.drift_z_threshold <= 0.0:
            raise ValueError(
                f"drift_z_threshold must be > 0, got {self.drift_z_threshold}"
            )

    @classmethod
    def from_env(cls) -> PipelineConfig:
        """Construct a :class:`PipelineConfig` from environment variables.

        Environment variables (see ``.env.example`` for full reference):

        * ``SPANFORGE_API_KEY``
        * ``SPANFORGE_ENDPOINT``
        * ``SPANFORGE_PROJECT_ID``
        * ``SPANFORGE_SIGNING_KEY``
        * ``SPANFORGE_LOCAL_FALLBACK``
        * ``OTEL_EXPORTER_OTLP_ENDPOINT``
        * ``CONFIDENCE_THRESHOLD``
        * ``DRIFT_Z_THRESHOLD``
        * ``AUDIT_OUTPUT_DIR``
        """
        api_key = _env("SPANFORGE_API_KEY")
        signing_key = _env("SPANFORGE_SIGNING_KEY") or _make_signing_key()

        local_fallback_raw = _env("SPANFORGE_LOCAL_FALLBACK", "true").lower()
        local_fallback = local_fallback_raw not in {"false", "0", "no"}

        if api_key and local_fallback:
            log.info(
                "SPANFORGE_API_KEY is set; disabling local fallback mode for cloud connectivity."
            )
            local_fallback = False

        return cls(
            api_key=api_key,
            endpoint=_env("SPANFORGE_ENDPOINT"),
            project_id=_env("SPANFORGE_PROJECT_ID", "meridian-loan-summary"),
            signing_key=signing_key,
            local_fallback=local_fallback,
            otel_endpoint=_env("OTEL_EXPORTER_OTLP_ENDPOINT"),
            confidence_threshold=_env_float("CONFIDENCE_THRESHOLD", 0.82),
            drift_z_threshold=_env_float("DRIFT_Z_THRESHOLD", 3.0),
            audit_output_dir=_env("AUDIT_OUTPUT_DIR", "./audit_output"),
        )

    def to_sf_client_config(self) -> object:
        """Return a ``SFClientConfig`` suitable for all SpanForge SDK clients."""
        # Import deferred to keep startup fast when SpanForge is not configured
        from spanforge.sdk.pii import (
            SFClientConfig,  # type: ignore[import-untyped, attr-defined, no-untyped-def]
        )

        return SFClientConfig(
            api_key=self.api_key,
            endpoint=self.endpoint,
            project_id=self.project_id,
            local_fallback_enabled=self.local_fallback,
            signing_key=self.signing_key,
        )
