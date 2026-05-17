# Runbook

Operational procedures for the Meridian Lending Co. AI pipeline.

---

## Alert: `AuditChainError` — HMAC Chain Tampered

**Severity:** Critical  
**TSC:** CC9.2

### Symptoms
- `pipeline.verify_audit_chain()` returns `False`
- `AuditChainError` is raised with `first_tampered` event ID
- Log line: `Audit chain integrity check FAILED`

### Response
1. **Isolate** — Stop accepting new pipeline invocations immediately.
2. **Preserve** — Copy the current `audit_chain.jsonl` to a read-only location before any investigation.
3. **Identify** — Note the `first_tampered` event ID and `gaps` list from the exception.
4. **Investigate** — Check filesystem audit logs for who accessed `PIPELINE_OUTPUT_DIR` around the tampered event's timestamp.
5. **Escalate** — Notify the security team and legal/compliance if data was exfiltrated.
6. **Restore** — Roll back from the last known-good audit chain snapshot.
7. **Document** — Record the incident, timeline, and remediation in the SOC 2 audit log.

---

## Alert: `PIIBlockedError` — Critical PII in Input

**Severity:** High  
**TSC:** CC6.6

### Symptoms
- Exception with `entity_types` containing `SSN`, `CREDIT_CARD`, or `BANK_ACCOUNT`
- Invocation aborted; no LLM output generated

### Response
1. Log the `invocation_id` and `entity_types` (not the raw PII).
2. Return a user-facing error: *"Application contains sensitive data that cannot be processed automatically.  Please contact your loan officer."*
3. Route the application to manual review.
4. If this occurs frequently for a specific `application_id` prefix, investigate the upstream document submission process for misconfiguration.

---

## Alert: `GateBlockedError` / `routed_to_human=true` — Low Confidence

**Severity:** Medium  
**TSC:** CC7.4

### Symptoms
- Gate decision record with `passed=false`
- `confidence` below `PIPELINE_CONFIDENCE_THRESHOLD` (default 0.82)

### Response
1. Queue the invocation for HITL review (send to human reviewer queue).
2. Do **not** surface the LLM output to the end user until a human reviewer approves it.
3. If escalation rate exceeds 10% over a rolling hour, investigate:
   - Is the LLM model performing as expected?
   - Has the input document quality degraded?
   - Has the confidence threshold been set too high?

---

## Alert: `DriftAlertError` — Metric Drift Breach

**Severity:** Medium  
**TSC:** CC7.2

### Symptoms
- `drift_alerts.jsonl` records with `status: "breach"`
- Metric: `response_length`, `confidence_score`, or `latency_ms`

### Response by Metric

| Metric | Likely Cause | Action |
|---|---|---|
| `response_length` breach | LLM producing unusually long/short outputs | Review recent prompts; check for prompt injection |
| `confidence_score` breach | Model degradation or distribution shift | Trigger model re-evaluation; consider rollback |
| `latency_ms` breach | Infrastructure slowdown | Check SpanForge endpoint health; review network |

For all metrics:
1. Check whether the breach correlates with a deployment, configuration change, or data change.
2. If `confidence_score` drifts low, increase monitoring frequency and review gate escalation rate.
3. Update `BaselineStats` after any intentional system change (e.g., model upgrade).

---

## Procedure: Rotating the Signing Key

**Frequency:** Per security policy (recommended: annually or on suspected compromise)

1. Generate a new key:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
2. Export and archive the current audit chain:
   ```python
   bundle = pipeline.export_evidence_bundle()
   # Archive bundle["audit_chain.jsonl"] to immutable storage
   ```
3. Update `SPANFORGE_SIGNING_KEY` in your secrets manager.
4. Restart the application.
5. Document the rotation date and operator in the SOC 2 change log.
6. Verify the new chain starts cleanly: `pipeline.verify_audit_chain()` should return `True` immediately.

---

## Procedure: Generating a Monthly Evidence Bundle

Schedule this as a cron job or CI pipeline task:

```python
from soc2_refimpl import LoanSummaryPipeline, PipelineConfig

config = PipelineConfig.from_env()
pipeline = LoanSummaryPipeline(config)

# Verify chain integrity first
if not pipeline.verify_audit_chain():
    raise RuntimeError("Audit chain integrity check failed — cannot export evidence")

bundle = pipeline.export_evidence_bundle()
print("Evidence bundle exported:", bundle)

# Optionally submit to SpanForge CEC
bundle_id = pipeline._compliance.build_cloud_bundle(
    period_start="2024-01-01",
    period_end="2024-01-31",
)
print("Cloud bundle ID:", bundle_id)

pipeline.close()
```

Archive the `PIPELINE_OUTPUT_DIR` contents to immutable storage at the end of each month.

---

## Procedure: Updating the Drift Baseline

When intentional system changes shift the expected metric distributions (e.g., after a model upgrade):

1. Collect 1000+ production observations to characterise the new distribution.
2. Compute the new `(mean, stddev)` for each metric.
3. Update `BaselineStats` defaults in `drift_monitor.py`:
   ```python
   @dataclass
   class BaselineStats:
       response_length: DistributionStats = (NEW_MEAN, NEW_STDDEV)
       confidence_score: DistributionStats = (NEW_MEAN, NEW_STDDEV)
       latency_ms: DistributionStats = (NEW_MEAN, NEW_STDDEV)
   ```
4. Run the full test suite to confirm nothing is broken.
5. Document the baseline change date and rationale in the SOC 2 change log.

---

## Procedure: Investigating a Compliance Exception

When any `ComplianceError` subclass is raised in production:

1. Retrieve the `invocation_id` from the exception context.
2. Find the corresponding record in `invocations.jsonl`.
3. Cross-reference `pii_redaction.jsonl`, `gate_escalations.jsonl`, and `drift_alerts.jsonl` using the `invocation_id`.
4. Determine whether the exception was expected (e.g., intentional PII block) or unexpected.
5. If unexpected: escalate according to severity (see alert sections above).

---

## Health Check Endpoint (Example)

Expose this in your API for liveness/readiness probes:

```python
from soc2_refimpl import LoanSummaryPipeline

def health_check(pipeline: LoanSummaryPipeline) -> dict:
    stats = pipeline._availability.get_stats()
    chain_ok = pipeline.verify_audit_chain()
    return {
        "status": "ok" if chain_ok else "degraded",
        "uptime_pct": stats.uptime_pct,
        "p99_ms": stats.p99_ms,
        "audit_chain_valid": chain_ok,
    }
```
