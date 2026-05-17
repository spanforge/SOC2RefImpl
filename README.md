# SOC2RefImpl

**SpanForge SOC 2 Reference Implementation — Meridian Lending Co.**

![Tests](https://img.shields.io/badge/tests-200%20passed-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-94.54%25-brightgreen)
![mypy](https://img.shields.io/badge/mypy-passing-blue)
![ruff](https://img.shields.io/badge/ruff-passing-blue)
![bandit](https://img.shields.io/badge/bandit-0%20issues-brightgreen)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

A production-grade reference implementation that demonstrates how to build **SOC 2 Type II compliant AI pipelines** using the [SpanForge SDK](https://www.getspanforge.com).  The scenario: a loan recommendation summarisation pipeline for Meridian Lending Co. that ingests applicant documents, generates LLM summaries, and enforces seven SOC 2 Trust Services Criteria at the code level.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -e .

# 2. Configure environment
cp .env.example .env
# Edit .env — at minimum set SPANFORGE_SIGNING_KEY

# 3. Run tests
pytest tests/ -q

# 4. Check coverage
pytest tests/ --cov=soc2_refimpl --cov-report=term-missing -q

# 5. Quality checks
mypy src/soc2_refimpl
ruff check src/ tests/
bandit -r src/ -c pyproject.toml
```

---

## Usage

```python
from soc2_refimpl import LoanSummaryPipeline, PipelineConfig

config = PipelineConfig.from_env()          # reads .env / environment
pipeline = LoanSummaryPipeline(config)

result = pipeline.run(
    application_id="APP-2024-001",
    documents=["Applicant earns $120k annually...", "Property value: $450k..."],
)

print(result.answer)          # redacted, gated, audited LLM output
print(result.span_id)         # OTel span ID (CC6.1)
print(result.gate_decision)   # GateDecision object (CC7.4)

# Export full SOC 2 evidence bundle
bundle = pipeline.export_evidence_bundle()
# → {"invocations.jsonl": "/path/...", "manifest.json": "/path/...", ...}

pipeline.close()
```

---

## SOC 2 Trust Services Criteria Coverage

| Criterion | Control | Module | Exception |
|---|---|---|---|
| **CC6.1** | Signed invocation spans | `availability.py` | — |
| **CC6.6** | PII detection and redaction | `pii_handler.py` | `PIIBlockedError` |
| **CC6.8** | LLM output secret detection | `secrets_scanner.py` | `SecretDetectedError` |
| **CC7.2** | Behavioural drift monitoring | `drift_monitor.py` | `DriftAlertError` |
| **CC7.4** | Confidence gate + HITL routing | `gate.py` | `GateBlockedError` |
| **CC9.2** | HMAC tamper-evident audit chain | `audit_chain.py` | `AuditChainError` |
| **A1.2** | Availability monitoring | `availability.py` | — |

---

## Architecture Overview

```
documents[]
    │
    ▼ CC6.6   PIIHandler          — scan_text() + anonymize() via SFPIIClient
    ▼         LLMBackend.generate()
    ▼ CC6.8   SecretsScanner      — scan() via SFSecretsClient
    ▼ CC7.2   DriftMonitor        — sliding window z-score via DriftDetector
    ▼ CC7.4   ComplianceGate      — evaluate() via SFGateClient
    ▼ CC9.2   AuditChain          — HMAC chain via AuditStream + SFAuditClient
    ▼ A1.2    AvailabilityMonitor — emit_span() via SFObserveClient
    │
    ▼
PipelineResult  →  ComplianceExporter  →  JSONL artefacts + manifest.json
```

---

## Repository Structure

```
src/soc2_refimpl/
├── __init__.py          Public API surface
├── config.py            PipelineConfig — env-driven configuration
├── exceptions.py        Typed compliance exceptions
├── models.py            Data transfer objects (RedactionRecord, GateDecision, …)
├── pii_handler.py       CC6.6 — PII scanning and redaction
├── secrets_scanner.py   CC6.8 — LLM output secret detection
├── drift_monitor.py     CC7.2 — Behavioural drift monitoring
├── gate.py              CC7.4 — Confidence gate and HITL routing
├── audit_chain.py       CC9.2 — HMAC tamper-evident audit chain
├── availability.py      A1.2  — Availability monitoring and OTel spans
├── compliance.py        Evidence aggregation and bundle export
└── pipeline.py          LoanSummaryPipeline — public entry point

tests/
├── conftest.py
├── test_config.py        26 tests
├── test_models.py        17 tests
├── test_exceptions.py    24 tests
├── test_pii_handler.py   16 tests
├── test_secrets_scanner.py 14 tests
├── test_drift_monitor.py 13 tests
├── test_gate.py          16 tests
├── test_audit_chain.py   16 tests
├── test_availability.py  15 tests
├── test_compliance.py    17 tests
└── test_pipeline.py      26 tests

docs/
├── index.md             Overview and quick start
├── architecture.md      System architecture and data flow
├── tsc-mapping.md       Per-criterion code-level mapping
├── deployment.md        Deployment guide and env vars
├── auditor-guide.md     Evidence review guide for auditors
└── runbook.md           Operational procedures and alert response
```

---

## Documentation

| Document | Audience |
|---|---|
| [docs/index.md](docs/index.md) | Everyone |
| [docs/architecture.md](docs/architecture.md) | Engineers |
| [docs/tsc-mapping.md](docs/tsc-mapping.md) | Engineers / Auditors |
| [docs/deployment.md](docs/deployment.md) | Platform / DevOps |
| [docs/auditor-guide.md](docs/auditor-guide.md) | Auditors / Compliance |
| [docs/runbook.md](docs/runbook.md) | Operations |

---

## Design Principles

- **Fail closed** — any compliance exception aborts the invocation; no partial outputs are returned.
- **No silent failures** — audit chain record failures emit warnings but never suppress the pipeline error.
- **All evidence is typed** — every artefact is a Pydantic/dataclass model with `.to_dict()` before JSONL serialisation.
- **Local fallback** — `SPANFORGE_LOCAL_FALLBACK=true` enables full offline operation for development and testing.

---

## License

MIT — see [LICENSE](LICENSE).

