"""
Shared pytest fixtures for the soc2_refimpl test suite.

All SpanForge clients use ``local_fallback_enabled=True`` so the tests run
without any network access or SpanForge cloud account.
"""

from __future__ import annotations

import pytest
from spanforge.testing_mocks import mock_all_services

from soc2_refimpl.config import PipelineConfig
from soc2_refimpl.pipeline import MockLLMBackend

# ---------------------------------------------------------------------------
# Signing key fixture — 32 hex chars (min length for HMAC-SHA256)
# ---------------------------------------------------------------------------
TEST_SIGNING_KEY = "a" * 64  # 64-char hex string → 256 bits


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_audit_dir(tmp_path: pytest.TempPathFactory) -> str:  # type: ignore[type-arg]
    """Return a temporary directory path for audit output."""
    return str(tmp_path)


@pytest.fixture
def base_config(tmp_audit_dir: str) -> PipelineConfig:
    """Minimal PipelineConfig for tests — no cloud, local fallback only."""
    return PipelineConfig(
        api_key="",
        endpoint="",
        project_id="test-project",
        signing_key=TEST_SIGNING_KEY,
        local_fallback=True,
        otel_endpoint="",
        confidence_threshold=0.82,
        drift_z_threshold=3.0,
        audit_output_dir=tmp_audit_dir,
        model="gpt-4o-mock",
    )


@pytest.fixture
def high_confidence_config(tmp_audit_dir: str) -> PipelineConfig:
    """Config with high confidence threshold (0.99) for gate-block testing."""
    return PipelineConfig(
        signing_key=TEST_SIGNING_KEY,
        local_fallback=True,
        confidence_threshold=0.99,
        audit_output_dir=tmp_audit_dir,
    )


@pytest.fixture
def low_threshold_config(tmp_audit_dir: str) -> PipelineConfig:
    """Config with very low confidence threshold (0.01) — gate always passes."""
    return PipelineConfig(
        signing_key=TEST_SIGNING_KEY,
        local_fallback=True,
        confidence_threshold=0.01,
        audit_output_dir=tmp_audit_dir,
    )


# ---------------------------------------------------------------------------
# LLM backend fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm() -> MockLLMBackend:
    """Standard mock LLM with confidence=0.91 (above default threshold)."""
    return MockLLMBackend(
        response="The applicant has a good credit profile. Approve.",
        confidence=0.91,
        latency_ms=0.0,  # no sleep in tests
    )


@pytest.fixture
def low_confidence_llm() -> MockLLMBackend:
    """Mock LLM with confidence=0.50 — below default gate threshold."""
    return MockLLMBackend(
        response="Uncertain recommendation.",
        confidence=0.50,
        latency_ms=0.0,
    )


@pytest.fixture
def safe_documents() -> list[str]:
    """Documents without PII — should pass PII handler unchanged."""
    return [
        "The applicant is a self-employed professional with steady income.",
        "Loan amount requested: $250,000 over 30 years at fixed rate.",
    ]


@pytest.fixture
def pii_documents() -> list[str]:
    """Documents containing PII entities (email, phone — non-critical)."""
    return [
        "Contact: john.smith@example.com, phone 555-123-4567.",
        "Employment status: Full-time, annual income: $95,000.",
    ]


@pytest.fixture
def critical_pii_documents() -> list[str]:
    """Documents containing critical PII (SSN) that must block processing."""
    return [
        "Social Security Number: 123-45-6789.",
    ]


@pytest.fixture
def utc_timestamp() -> str:
    """Return a fixed UTC timestamp for deterministic assertions."""
    return "2026-01-15T10:00:00+00:00"


# ---------------------------------------------------------------------------
# SpanForge service mock fixture (DX-003 — spanforge.testing_mocks)
# ---------------------------------------------------------------------------


@pytest.fixture
def sf_mocks():
    """Context-managed mock for all SpanForge SDK service clients.

    Replaces every SDK singleton (sf_pii, sf_audit, sf_secrets, sf_gate, etc.)
    with an in-memory mock for the duration of the test.  Each mock records
    all calls in ``.calls`` and returns sensible defaults without network I/O.

    Usage::

        def test_something(sf_mocks):
            # all SDK calls are intercepted
            handler = PIIHandler(base_config)
            handler.process_documents(["Hello"])
            assert sf_mocks.pii.calls  # verify calls were made
    """
    with mock_all_services() as mocks:
        yield mocks
