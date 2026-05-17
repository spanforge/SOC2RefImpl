# Deployment Guide

## Environment Variables Reference

All configuration is driven by environment variables.  Copy `.env.example` to `.env` before deploying.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SPANFORGE_API_KEY` | No* | `""` | SpanForge cloud API key |
| `SPANFORGE_ENDPOINT` | No | `https://api.getspanforge.com` | SpanForge API endpoint |
| `SPANFORGE_PROJECT_ID` | No | `meridian-loan-summary` | Project identifier |
| `SPANFORGE_SIGNING_KEY` | **Yes** | — | Hex string ≥ 32 bytes; used for HMAC audit chain |
| `SPANFORGE_TIMEOUT_MS` | No | `5000` | API timeout in milliseconds |
| `SPANFORGE_MAX_RETRIES` | No | `3` | Number of API retries |
| `SPANFORGE_LOCAL_FALLBACK` | No | `true` | Enable offline mode |
| `SPANFORGE_TLS_VERIFY` | No | `true` | Verify TLS certificates |
| `SPANFORGE_OTEL_ENDPOINT` | No | `""` | OpenTelemetry collector endpoint |
| `PIPELINE_CONFIDENCE_THRESHOLD` | No | `0.82` | Minimum gate confidence (0–1) |
| `PIPELINE_DRIFT_Z_THRESHOLD` | No | `3.0` | Drift z-score breach threshold |
| `PIPELINE_OUTPUT_DIR` | No | `./audit_output` | Directory for evidence artefacts |

*`SPANFORGE_API_KEY` is only required when `SPANFORGE_LOCAL_FALLBACK=false`.

### Generating a Signing Key

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Store the output in `SPANFORGE_SIGNING_KEY`.  **Never commit this value to source control.**

---

## Day-0 Checklist (New Deployment)

- [ ] Generate a 32-byte signing key and store in secrets manager
- [ ] Set `SPANFORGE_LOCAL_FALLBACK=false` and provide `SPANFORGE_API_KEY`
- [ ] Configure `SPANFORGE_OTEL_ENDPOINT` to point at your OTel collector
- [ ] Set `PIPELINE_OUTPUT_DIR` to a persistent, access-controlled path
- [ ] Set `SPANFORGE_TLS_VERIFY=true` (never disable in production)
- [ ] Verify pipeline runs end-to-end: `python -m pytest tests/ -q`
- [ ] Run `pipeline.verify_audit_chain()` after first production invocations

## Day-1 Checklist (Operational Handoff)

- [ ] Schedule `pipeline.export_evidence_bundle()` for daily evidence collection
- [ ] Set up monitoring alert on `DriftAlertError` and `AuditChainError`
- [ ] Confirm `AvailabilityMonitor.get_stats().uptime_pct` is visible in dashboards
- [ ] Rotate `SPANFORGE_SIGNING_KEY` per your key rotation policy (see Runbook)

---

## Local Development / Testing

```bash
# All tests use local_fallback=True — no cloud credentials needed
pytest tests/ -q

# Coverage report
pytest tests/ --cov=soc2_refimpl --cov-report=term-missing -q

# Type checking
mypy src/soc2_refimpl

# Lint
ruff check src/ tests/

# Security scan
bandit -r src/ -c pyproject.toml
```

---

## Production Considerations

### Key Rotation

1. Generate a new signing key.
2. Update `SPANFORGE_SIGNING_KEY` in your secrets manager.
3. Restart the application.
4. Export and archive the existing `audit_chain.jsonl` before rotation — the old chain cannot be verified with the new key.
5. Start a new audit chain period (document the rotation date in your SOC 2 audit log).

### Scaling

`LoanSummaryPipeline` is **not** thread-safe by default.  Instantiate one pipeline per worker thread/process.  The `AvailabilityMonitor` uses a `threading.Lock` internally, so `record_invocation()` is safe to call concurrently from a single instance if needed.

### Audit Output Storage

The `PIPELINE_OUTPUT_DIR` directory contains compliance-sensitive data.  In production:
- Mount on encrypted block storage
- Apply least-privilege filesystem ACLs (the process user should be the only writer)
- Rotate JSONL files daily and archive to immutable object storage (e.g., S3 with Object Lock)

### LLM Backend

The `LLMBackend` protocol allows any provider:
```python
class MyLLMBackend:
    def generate(self, prompt: str) -> tuple[str, float]:
        # Returns (answer_text, confidence_score 0.0–1.0)
        ...

pipeline = LoanSummaryPipeline(config, llm=MyLLMBackend())
```

The default `MockLLMBackend` is for testing only.

---

## Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e .

ENV SPANFORGE_LOCAL_FALLBACK=false
ENV SPANFORGE_TLS_VERIFY=true

CMD ["python", "-m", "soc2_refimpl.pipeline"]
```

Secrets should be injected via your orchestrator's secret management (Kubernetes Secrets, AWS Secrets Manager, Azure Key Vault, etc.) — never baked into the image.
