# SOC 2 Reference Implementation — Documentation

> **Meridian Lending Co. · SpanForge 2.0 · Python 3.11+**

This repository is a production-grade reference implementation that demonstrates how to build a SOC 2 Type II–compliant AI pipeline using the [SpanForge](https://www.getspanforge.com) SDK.  The scenario: a GPT-4o–powered loan-recommendation summariser at an enterprise lender, subject to SOC 2 Type II audit.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/your-org/soc2-refimpl
cd soc2-refimpl
pip install -e ".[dev]"

# 2. Copy and configure environment variables
cp .env.example .env
# Edit .env — set SPANFORGE_API_KEY, etc. (all fields have local-fallback defaults)

# 3. Run the full test suite
pytest tests/                          # 200 tests, ≥ 90% coverage

# 4. Run quality checks
mypy src/soc2_refimpl
ruff check src/ tests/
bandit -r src/ -c pyproject.toml

# 5. Try the pipeline
python -c "
from soc2_refimpl import LoanSummaryPipeline, PipelineConfig
cfg = PipelineConfig(signing_key='a'*64)          # use from_env() in production
pipeline = LoanSummaryPipeline(cfg)
result = pipeline.run('APP-001', ['Applicant earns \$120k/yr…'])
print(result.invocation.status, result.invocation.gate_passed)
pipeline.close()
"
```

---

## Documentation Index

| Document | Purpose |
|---|---|
| [Architecture](architecture.md) | System diagram, module responsibilities, data flows |
| [TSC Mapping](tsc-mapping.md) | Detailed code-level mapping for each SOC 2 TSC criterion |
| [Deployment](deployment.md) | Environment variables, Day-0 checklist, production considerations |
| [Auditor Guide](auditor-guide.md) | How to generate and interpret the evidence bundle |
| [Runbook](runbook.md) | Operational procedures and incident response |

---

## What Is Covered

| SOC 2 Criterion | Control | SpanForge API |
|---|---|---|
| CC6.1 | Signed invocation spans | `@trace` / `SFObserveClient` |
| CC6.6 | PII redaction before LLM | `SFPIIClient` |
| CC6.8 | Secret detection in output | `SFSecretsClient` |
| CC7.2 | Behavioural drift monitoring | `DriftDetector` / `BehaviouralBaseline` |
| CC7.4 | Confidence gate + HITL routing | `SFGateClient` |
| CC9.2 | HMAC audit chain integrity | `AuditStream` / `SFAuditClient` |
| A1.2 | Availability tracking (p50/p95/p99) | `SFObserveClient` |

---

## Repository Layout

```
src/soc2_refimpl/
├── __init__.py          # Public API exports
├── config.py            # PipelineConfig dataclass
├── exceptions.py        # Typed compliance exceptions
├── models.py            # PipelineResult, InvocationRecord, etc.
├── pii_handler.py       # CC6.6 — PII redaction
├── secrets_scanner.py   # CC6.8 — secret detection
├── drift_monitor.py     # CC7.2 — drift detection
├── gate.py              # CC7.4 — confidence gate
├── audit_chain.py       # CC9.2 — HMAC audit chain
├── availability.py      # A1.2  — availability monitoring
├── compliance.py        # Evidence bundle export (CEC)
└── pipeline.py          # Main orchestrator

tests/                   # 200 tests, 94%+ coverage
docs/                    # This documentation
implementationplan.md    # 10-section implementation plan
```

---

## Key Design Principles

1. **Local-fallback mode** — all SpanForge clients work offline (`local_fallback=True`).  Tests never make network calls.
2. **Typed exception hierarchy** — every compliance violation raises a specific exception (`PIIBlockedError`, `GateBlockedError`, etc.) that carries the TSC criterion code.
3. **Immutable audit trail** — `AuditStream` signs every event with HMAC-SHA256; `AuditChain.verify()` detects any tampering.
4. **Evidence bundle** — `ComplianceExporter.export_local()` writes JSONL artefacts + a manifest suitable for auditor handoff.
5. **No secrets at rest** — `PipelineConfig` reads credentials from environment variables; the signing key is never logged.
