# Auditor Guide

> This guide is written for SOC 2 auditors and internal compliance reviewers who need to inspect the evidence produced by the Meridian Lending Co. AI pipeline.

---

## Evidence Bundle Structure

Run the following to generate the full evidence bundle:

```python
from soc2_refimpl import LoanSummaryPipeline, PipelineConfig

config = PipelineConfig.from_env()
pipeline = LoanSummaryPipeline(config)

# ... run invocations ...

bundle = pipeline.export_evidence_bundle()
# Returns: {"invocations.jsonl": "/path/to/...", "manifest.json": "/path/to/...", ...}
pipeline.close()
```

The bundle directory (`PIPELINE_OUTPUT_DIR`) will contain:

| File | TSC | Contents |
|---|---|---|
| `manifest.json` | All | Bundle metadata, TSC coverage summary, artefact index |
| `invocations.jsonl` | CC6.1 | One record per pipeline invocation |
| `pii_redaction.jsonl` | CC6.6 | PII entities detected and redacted per document |
| `secrets_scan.jsonl` | CC6.8 | Secrets detection results per LLM output |
| `drift_alerts.jsonl` | CC7.2 | Metric drift breach events |
| `gate_escalations.jsonl` | CC7.4 | All gate decisions (pass and block) |
| `audit_chain.jsonl` | CC9.2 | HMAC-chained event log |
| `availability_stats.json` | A1.2 | Uptime percentage and latency percentiles |

---

## Manifest (`manifest.json`)

The manifest is always the starting point for audit review.  Example:

```json
{
  "service": "meridian-loan-summary",
  "generated_at": "2024-01-15T10:00:00Z",
  "bundle_id": "bundle-abc123",
  "spans_total": 1000,
  "tsc_mapping": {
    "CC6.1": "1000 traced invocations",
    "CC6.6": "247 PII entities redacted across 500 documents",
    "CC6.8": "3 secrets detected in output",
    "CC7.2": "2 drift alerts",
    "CC7.4": "18 escalations to human review",
    "CC9.2": "HMAC chain — verify with audit_chain.verify()",
    "A1.2": "99.80% uptime; p99 latency 1450ms"
  },
  "artifacts": {
    "invocations.jsonl": "/audit_output/invocations.jsonl",
    ...
  }
}
```

Key fields to verify:
- `spans_total` matches the count in `invocations.jsonl`
- `tsc_mapping` values are consistent with the individual JSONL files
- `generated_at` falls within the audit period

---

## Verifying HMAC Chain Integrity (CC9.2)

The most critical artefact is the HMAC audit chain.  Verify it programmatically:

```python
from soc2_refimpl import LoanSummaryPipeline, PipelineConfig

config = PipelineConfig.from_env()
pipeline = LoanSummaryPipeline(config)

is_valid = pipeline.verify_audit_chain()
print("Chain intact:", is_valid)
```

If tampered events exist, `AuditChainError` will be raised (or `verify_audit_chain()` returns `False`) with the following information:
- `first_tampered` — event ID of the first tampered event
- `gaps` — list of missing sequence numbers

You can also inspect the raw HMAC chain records in `audit_chain.jsonl`.  Each record contains:
- `event_id` — unique ULID
- `event_type` — one of `AUDIT_EVENT_SIGNED`, `TRACE_SPAN_COMPLETED`, etc.
- `source` — `"meridian-loan-summary"`
- `payload` — event-specific data (invocation ID, metrics, gate decision, etc.)

---

## Reviewing PII Redaction (CC6.6)

Each record in `pii_redaction.jsonl`:

```json
{
  "invocation_id": "inv-7f3a2b",
  "document_index": 0,
  "entity_types": ["SSN", "EMAIL_ADDRESS"],
  "detected": true,
  "redacted_text": "Applicant <SSN> earns $120k. Contact: <EMAIL_ADDRESS>",
  "timestamp": "2024-01-15T10:01:23Z"
}
```

Key assertions:
- `redacted_text` should contain typed placeholders (e.g., `<SSN>`) — never raw PII values
- If `entity_types` contains `SSN`, `CREDIT_CARD`, or `BANK_ACCOUNT`, the invocation must have completed (the block mechanism raised `PIIBlockedError` and the pipeline aborted)

---

## Reviewing Gate Decisions (CC7.4)

Each record in `gate_escalations.jsonl`:

```json
{
  "invocation_id": "inv-7f3a2b",
  "gate_id": "loan-summary-confidence",
  "confidence": 0.75,
  "threshold": 0.82,
  "passed": false,
  "routed_to_human": true,
  "verdict": "FAIL",
  "timestamp": "2024-01-15T10:01:23Z"
}
```

Key assertions:
- All records with `passed=false` should have `routed_to_human=true`
- `confidence` values should match the invocation's confidence in `invocations.jsonl`
- The `threshold` value should match `PIPELINE_CONFIDENCE_THRESHOLD` in the deployment config

---

## Reviewing Drift Alerts (CC7.2)

Each record in `drift_alerts.jsonl`:

```json
{
  "invocation_id": "inv-8c4d1e",
  "metric_name": "response_length",
  "window_mean": 820.5,
  "window_stddev": 88.2,
  "window_count": 25,
  "z_threshold": 3.0,
  "status": "breach",
  "tsc": "CC7.2",
  "timestamp": "2024-01-15T10:05:00Z"
}
```

A `breach` means the metric's rolling mean deviated from the baseline by more than `z_threshold` standard deviations.

---

## Reviewing Availability (A1.2)

`availability_stats.json` provides a point-in-time snapshot:

```json
{
  "total_invocations": 1000,
  "error_count": 2,
  "uptime_pct": 99.8,
  "p50_ms": 1180.0,
  "p95_ms": 1450.0,
  "p99_ms": 1620.0
}
```

Cross-reference `total_invocations` with the count of records in `invocations.jsonl`.

---

## Cloud Bundle (Optional)

If `SPANFORGE_API_KEY` is configured, the pipeline can also submit a compliance bundle to the SpanForge Evidence Chain (CEC) service:

```python
bundle_id = await pipeline._compliance.build_cloud_bundle(
    period_start="2024-01-01",
    period_end="2024-01-31",
)
print("Cloud bundle ID:", bundle_id)
```

The `bundle_id` returned can be provided to the auditor for independent verification via the SpanForge CEC portal.

---

## Evidence Completeness Checklist

| Criterion | Evidence | Verification Method |
|---|---|---|
| CC6.1 | `invocations.jsonl` + `span_id` field | Count spans ≥ total invocations |
| CC6.6 | `pii_redaction.jsonl` | All docs present; no raw PII in `redacted_text` |
| CC6.8 | `secrets_scan.jsonl` | One record per invocation |
| CC7.2 | `drift_alerts.jsonl` | Alerts correlate with anomalous periods |
| CC7.4 | `gate_escalations.jsonl` | `passed=false` → `routed_to_human=true` |
| CC9.2 | `audit_chain.jsonl` + `verify_audit_chain()` | Returns `True` |
| A1.2 | `availability_stats.json` | `uptime_pct` meets SLA threshold |
