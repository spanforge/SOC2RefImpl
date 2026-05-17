# TSC Criterion to Code Mapping

This document traces each SOC 2 Trust Services Criterion to the exact source code that implements it.

---

## CC6.1 — Logical Access Controls / Signed Invocation Spans

> *The entity restricts logical access to information assets.*

**Implementation:** Every pipeline invocation emits a cryptographically signed span via SpanForge's `SFObserveClient`.

| Artefact | Location |
|---|---|
| Span emission | `availability.py` → `AvailabilityMonitor.record_invocation()` |
| Span ID stored | `models.py` → `InvocationRecord.span_id` |
| Test | `tests/test_availability.py` |

```python
# availability.py
span_id = self._client.emit_span(
    f"loan_summary.{invocation_id}",
    attributes={"success": success, "duration_ms": duration_ms, ...},
)
```

Each span is written to the OTel endpoint configured via `SPANFORGE_OTEL_ENDPOINT`.

---

## CC6.6 — Restriction of Access to Sensitive Data (PII Redaction)

> *The entity implements controls to prevent unauthorized disclosure of sensitive information.*

**Implementation:** All raw documents are scanned and redacted by `PIIHandler` **before** being passed to the LLM.  Critical PII (`SSN`, `CREDIT_CARD`, `BANK_ACCOUNT`) triggers a hard block.

| Artefact | Location |
|---|---|
| Scan + redact | `pii_handler.py` → `PIIHandler.scan_and_redact()` |
| Block logic | `pii_handler.py` lines 88–96 |
| Exception | `exceptions.py` → `PIIBlockedError` |
| Audit record | `models.py` → `RedactionRecord` |
| Pipeline integration | `pipeline.py` lines 172–189 |
| Test | `tests/test_pii_handler.py` |

```python
# pii_handler.py — critical PII block
if detected_types and any(t in _CRITICAL_ENTITY_TYPES for t in detected_types):
    raise PIIBlockedError(detected_types)
```

Evidence artefact: `pii_redaction.jsonl` — one record per document, containing `invocation_id`, `entity_types`, `redacted_text`, and `timestamp`.

---

## CC6.8 — Detection of Unauthorized Changes (Secret Detection)

> *The entity monitors for and detects unauthorized changes to configurations or data.*

**Implementation:** The raw LLM output is scanned for credentials, tokens, and secrets by `SecretsScanner` before it is returned to any caller.

| Artefact | Location |
|---|---|
| Scan | `secrets_scanner.py` → `SecretsScanner.scan()` |
| Block mode | `secrets_scanner.py` → constructor `block_on_detection=False` |
| Exception | `exceptions.py` → `SecretDetectedError` |
| Audit record | `models.py` → `SecretScanRecord` |
| Pipeline integration | `pipeline.py` lines 192–206 |
| Test | `tests/test_secrets_scanner.py` |

```python
# secrets_scanner.py — hard block option
if self._block_on_detection and scan_result.detected:
    raise SecretDetectedError(scan_result.secret_types or [])
```

Evidence artefact: `secrets_scan.jsonl`.

---

## CC7.2 — Monitoring of System Performance (Behavioural Drift)

> *The entity monitors system components and the operation of those components for anomalies.*

**Implementation:** Three metrics (response length, confidence score, latency) are fed into a sliding-window drift detector per invocation.  Breaches are logged to the audit chain.

| Artefact | Location |
|---|---|
| Baseline | `drift_monitor.py` → `BaselineStats` |
| Observation | `drift_monitor.py` → `DriftObservation` |
| Drift logic | `drift_monitor.py` → `DriftMonitor.observe()` |
| Alert payload | `drift_monitor.py` → `DriftMonitor.make_alert_payload()` |
| Exception | `exceptions.py` → `DriftAlertError` |
| Pipeline integration | `pipeline.py` lines 209–229 |
| Test | `tests/test_drift_monitor.py` |

```python
# pipeline.py — drift observation per invocation
obs = DriftObservation(
    response_length=float(len(answer)),
    confidence_score=confidence,
    latency_ms=elapsed_ms,
    invocation_id=invocation_id,
)
breach_metrics = self._drift.observe(obs)
```

Evidence artefact: `drift_alerts.jsonl` — one record per breach metric, containing mean, stddev, window count, z-threshold, and timestamp.

---

## CC7.4 — Evaluation of Processing Integrity (Confidence Gate + HITL)

> *The entity evaluates the completeness and accuracy of system outputs.*

**Implementation:** Every LLM response is evaluated against a minimum confidence threshold by `ComplianceGate`.  Responses below the threshold are flagged for human review.

| Artefact | Location |
|---|---|
| Gate evaluation | `gate.py` → `ComplianceGate.evaluate()` |
| Gate ID | `gate.py` → `gate_id = "loan-summary-confidence"` |
| Threshold | `config.py` → `PipelineConfig.confidence_threshold` (default 0.82) |
| Exception | `exceptions.py` → `GateBlockedError` |
| Decision record | `models.py` → `GateDecision` |
| Pipeline integration | `pipeline.py` lines 231–248 |
| Test | `tests/test_gate.py` |

```python
# gate.py — threshold fallback (local mode)
verdict = GateVerdict.PASS if confidence >= self._threshold else GateVerdict.FAIL
passed = verdict == GateVerdict.PASS
```

When `passed=False`, the `GateDecision.routed_to_human` flag is set and the response is annotated for HITL queue routing.

Evidence artefact: `gate_escalations.jsonl` — **all** decisions recorded, not just escalations.

---

## CC9.2 — Monitoring of Internal Controls (HMAC Audit Chain)

> *The entity monitors the effectiveness of internal controls.*

**Implementation:** Every significant pipeline event is appended to a tamper-evident HMAC chain.  Each event is linked to the previous via HMAC-SHA256 so any deletion, modification, or insertion is detected by `AuditChain.verify()`.

| Artefact | Location |
|---|---|
| Chain management | `audit_chain.py` → `AuditChain` |
| HMAC stream | SpanForge `AuditStream` |
| Cloud store | SpanForge `SFAuditClient` |
| Integrity check | `audit_chain.py` → `AuditChain.verify()` |
| Exception | `exceptions.py` → `AuditChainError` |
| Export | `audit_chain.py` → `AuditChain.export_jsonl()` |
| Pipeline integration | `pipeline.py` → `export_evidence_bundle()` and `verify_audit_chain()` |
| Test | `tests/test_audit_chain.py` |

```python
# pipeline.py — verify before export
def export_evidence_bundle(self) -> dict[str, str]:
    self._audit.verify()           # raises AuditChainError if tampered
    paths = self._compliance.export_local()
    return {name: str(path) for name, path in paths.items()}
```

Evidence artefact: `audit_chain.jsonl` — exported via `SFAuditClient.export()`.

---

## A1.2 — Availability Monitoring

> *The entity monitors system capacity to meet processing commitments.*

**Implementation:** Each invocation records a span with duration and success flag.  A sliding deque tracks the last 1000 invocations to compute uptime percentage and latency percentiles.

| Artefact | Location |
|---|---|
| Monitor | `availability.py` → `AvailabilityMonitor` |
| Stats | `availability.py` → `AvailabilityStats` |
| Pipeline integration | `pipeline.py` lines 253–261 |
| Manifest field | `compliance.py` → `tsc_mapping["A1.2"]` |
| Test | `tests/test_availability.py` |

```python
# availability.py — stats calculation
@property
def uptime_pct(self) -> float:
    if self.total_invocations == 0:
        return 100.0
    return 100.0 * (1 - self.error_count / self.total_invocations)
```

Evidence artefact: `availability_stats.json` — contains `uptime_pct`, `p50_ms`, `p95_ms`, `p99_ms`, `total_invocations`, `error_count`.

---

## Summary Matrix

| TSC | Control | Module | Exception | Evidence Artefact |
|---|---|---|---|---|
| CC6.1 | Signed spans | `availability.py` | — | OTel endpoint |
| CC6.6 | PII redaction | `pii_handler.py` | `PIIBlockedError` | `pii_redaction.jsonl` |
| CC6.8 | Secret detection | `secrets_scanner.py` | `SecretDetectedError` | `secrets_scan.jsonl` |
| CC7.2 | Drift monitoring | `drift_monitor.py` | `DriftAlertError` | `drift_alerts.jsonl` |
| CC7.4 | Confidence gate | `gate.py` | `GateBlockedError` | `gate_escalations.jsonl` |
| CC9.2 | HMAC audit chain | `audit_chain.py` | `AuditChainError` | `audit_chain.jsonl` |
| A1.2 | Availability | `availability.py` | — | `availability_stats.json` |
