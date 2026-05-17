# Architecture

## Overview

`soc2_refimpl` is a thin orchestration layer that wires SpanForge SDK primitives together into a single, auditable AI pipeline.  Every invocation of `LoanSummaryPipeline.run()` executes the following stages in order:

```
application_id + documents
        │
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      LoanSummaryPipeline.run()                      │
│                                                                     │
│  1. PIIHandler.scan_and_redact()          CC6.6  SFPIIClient       │
│  2. LLMBackend.generate()                 (user-supplied)           │
│  3. SecretsScanner.scan()                 CC6.8  SFSecretsClient   │
│  4. DriftMonitor.observe()                CC7.2  DriftDetector      │
│  5. ComplianceGate.evaluate()             CC7.4  SFGateClient       │
│  6. AuditChain.record_*()                 CC9.2  AuditStream        │
│  7. AvailabilityMonitor.record_invoc()    A1.2   SFObserveClient   │
│                                                                     │
│  returns PipelineResult                                             │
└─────────────────────────────────────────────────────────────────────┘
        │
        ▼
ComplianceExporter.export_local()   →  JSONL artefacts + manifest
ComplianceExporter.build_cloud_bundle() →  SFCECClient bundle
```

---

## Module Responsibilities

### `config.py` — `PipelineConfig`
Central configuration dataclass.  Reads from environment variables via `from_env()`.  Exposes `to_sf_client_config()` which returns an `SFClientConfig` consumed by all SpanForge SDK clients.

Key fields:
- `signing_key` — 32-byte minimum hex key for HMAC chain
- `confidence_threshold` — minimum gate confidence (default 0.82)
- `drift_z_threshold` — z-score breach threshold (default 3.0)
- `local_fallback` — enables offline mode for all SDK clients

### `exceptions.py` — typed compliance exceptions

```
ComplianceError (base)
├── PIIBlockedError       CC6.6  — critical PII cannot be redacted
├── SecretDetectedError   CC6.8  — secret in LLM output (block_on_detection=True)
├── DriftAlertError       CC7.2  — metric drift breach
├── GateBlockedError      CC7.4  — confidence gate blocked response
└── AuditChainError       CC9.2  — HMAC chain integrity failure
```

Every exception carries a `tsc_criterion` attribute so callers can log precisely which SOC 2 control was triggered.

### `models.py` — data transfer objects

| Class | Purpose |
|---|---|
| `RedactionRecord` | One PII redaction per document |
| `SecretScanRecord` | One secrets scan of LLM output |
| `GateDecision` | Gate pass/fail + routing decision |
| `InvocationRecord` | Full per-invocation summary |
| `PipelineResult` | Returned by `run()` |

All models have a `.to_dict()` method for JSONL serialisation.

### `pii_handler.py` — `PIIHandler` (CC6.6)
Calls `SFPIIClient.scan_text()` then `SFPIIClient.anonymize()` on each document.  If critical PII (`SSN`, `CREDIT_CARD`, `BANK_ACCOUNT`) is detected and anonymization fails, raises `PIIBlockedError`.

### `secrets_scanner.py` — `SecretsScanner` (CC6.8)
Calls `SFSecretsClient.scan()` on the LLM output.  When `block_on_detection=True` and secrets are found, raises `SecretDetectedError`.  Otherwise returns a `SecretScanRecord`.

### `drift_monitor.py` — `DriftMonitor` (CC7.2)
Wraps SpanForge `DriftDetector` + `BehaviouralBaseline`.  Each `observe()` call feeds three metrics (response length, confidence score, latency) into the sliding window.  Breaches are recorded via `make_alert_payload()`.

`BaselineStats` provides the historical baseline:
```python
@dataclass
class BaselineStats:
    response_length: tuple[float, float] = (500.0, 100.0)   # (mean, stddev)
    confidence_score: tuple[float, float] = (0.88, 0.06)
    latency_ms: tuple[float, float] = (1200.0, 300.0)
```

### `gate.py` — `ComplianceGate` (CC7.4)
Calls `SFGateClient.evaluate()` with the gate ID `"loan-summary-confidence"`.  Falls back to threshold-only evaluation in local mode.  Returns a `GateDecision` and sets `routed_to_human=True` when confidence is below threshold.

### `audit_chain.py` — `AuditChain` (CC9.2)
Maintains two parallel stores:
- **`AuditStream`** — in-process HMAC chain (tamper-evident event log)
- **`SFAuditClient`** — cloud audit store (for long-term retention)

All `record_*()` methods are non-fatal: store failures are logged as warnings so the pipeline never fails due to audit infrastructure issues.  `verify()` checks HMAC integrity and raises `AuditChainError` on tampering.

### `availability.py` — `AvailabilityMonitor` (A1.2)
Emits an OTel span via `SFObserveClient.emit_span()` for each invocation.  Maintains a sliding window (`collections.deque`) to compute p50/p95/p99 latency percentiles.  `get_stats()` returns an `AvailabilityStats` object with uptime percentage (100.0 when no invocations have been recorded).

### `compliance.py` — `ComplianceExporter`
Aggregates all artefacts across the pipeline lifecycle and exports them:
- `export_local()` — writes JSONL files + manifest JSON to `output_dir`
- `build_cloud_bundle()` — calls `SFCECClient.build_bundle()` for cloud submission

Manifest keys: `service`, `generated_at`, `bundle_id`, `spans_total`, `artifacts`, `tsc_mapping`, `tsc_descriptions`.

### `pipeline.py` — `LoanSummaryPipeline`
The public entry point.  Instantiates all components in `__init__` and orchestrates them in `run()`.  Three public methods:
- `run(application_id, documents, *, confidence_override=None)` → `PipelineResult`
- `export_evidence_bundle()` → `dict[str, str]` — calls `verify()` then `export_local()`
- `verify_audit_chain()` → `bool` — returns `False` on `AuditChainError`

---

## Data Flow Diagram

```
documents[]
    │
    ▼  CC6.6
PIIHandler
    │  clean_docs[] + RedactionRecord[]
    ▼
LLMBackend.generate()
    │  answer + confidence
    ▼  CC6.8
SecretsScanner
    │  answer (possibly redacted) + SecretScanRecord
    ▼  CC7.2
DriftMonitor.observe()
    │  breach_metrics[]
    ▼  CC7.4
ComplianceGate.evaluate()
    │  GateDecision (passed / routed_to_human)
    ▼  CC9.2
AuditChain.record_*()   ──────────────────────────────────┐
    │                                                       │
    ▼  A1.2                                           AuditStream
AvailabilityMonitor.record_invocation()              (HMAC chain)
    │
    ▼
PipelineResult
    │
    ▼
ComplianceExporter
    ├── invocations.jsonl
    ├── pii_redaction.jsonl
    ├── secrets_scan.jsonl
    ├── drift_alerts.jsonl
    ├── gate_escalations.jsonl
    ├── audit_chain.jsonl
    ├── availability_stats.json
    └── manifest.json
```

---

## Dependency Graph

```
pipeline.py
 ├── config.py
 ├── models.py
 ├── exceptions.py
 ├── pii_handler.py      → config.py
 ├── secrets_scanner.py  → config.py, models.py, exceptions.py
 ├── drift_monitor.py    → config.py
 ├── gate.py             → config.py, models.py, exceptions.py
 ├── audit_chain.py      → config.py, models.py, exceptions.py
 ├── availability.py     → config.py
 └── compliance.py       → config.py, models.py, audit_chain.py, availability.py
```

No circular imports.  All SpanForge SDK imports are guarded with `# type: ignore` (SDK stubs are partially typed) and declared in the `mypy` override section of `pyproject.toml`.
