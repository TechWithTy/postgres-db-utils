# Best Practices for CPU-Intensive API Endpoints

This guide covers production-ready patterns for building and securing CPU-intensive API routes using the project's db_utils and supporting utilities. These recommendations ensure safe, efficient, and scalable handling of heavy computation in FastAPI.

---

## 1. Offload to Background Workers (Pulsar/Valkey)
- Use Pulsar topics and/or Valkey pub/sub lists for long-running CPU-bound tasks.
- Trigger jobs from API endpoints by publishing to a Pulsar topic or Valkey queue; return a job/task ID for polling or webhook notification.
- Combine Pulsar (for fan-out, durability, and replay) with Valkey (for fast queueing or hybrid patterns) if needed.
- Avoid blocking the event loop or main API process with heavy computation; all heavy work should be handled by worker processes consuming from Pulsar or Valkey.

## 2. Rate Limiting & Abuse Protection
- Apply strict per-user and per-IP rate limits to CPU-intensive endpoints using real Valkey-backed algorithms.
- Use `is_allowed_token_bucket` or sliding window pattern for burst control (see code example below).
- Consider global concurrency limits for resource-heavy jobs.

## 3. Credits & Quotas
- Require credits/quota for all CPU-intensive operations using `call_function_with_credits` before job submission.
- Deduct credits atomically and reject if quota is exceeded (see code example).

## 4. Input Validation & Security
- Use Pydantic models for strict input validation.
- Sanitize and validate all parameters to prevent resource exhaustion or DoS.
- Enforce authentication and RBAC (user role permissions) for all heavy endpoints. Always check user roles using dependencies such as `roles_required(["cpu_user"])` or `require_scope("run:cpu_job")`.

## 5. Monitoring & Metrics
- Track job submission, queue wait, execution time, and errors using Prometheus metrics.
- Set up alerts for high error rates, long queue times, or excessive resource usage.
- Use OpenTelemetry for tracing job lifecycles end-to-end.

## 6. Idempotency & Deduplication
- Use Valkey or DB-backed idempotency keys to prevent duplicate job execution.
- Return the same result for repeated requests with the same idempotency key.

---

## Example: Secure, Rate-Limited, Credit-Enforced, MFA-Protected CPU Job Endpoint

---

## Circuit Breaker & Retry Logic for CPU-Intensive Endpoints

For CPU tasks that may fail due to transient errors or external service dependencies, use `circuit` (circuit breaker) and `retry_decorator` to improve reliability and resilience.

**Example:**
```python
CopyInsert
decorated_func = trace_function(...)(cpu_job_logic)
decorated_func = track_errors(decorated_func)
decorated_func = measure_performance(...)(decorated_func)
decorated_func = circuit(failure_threshold=5, recovery_timeout=30)(decorated_func)
decorated_func = retry_decorator(max_retries=3)(decorated_func)
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing

# Apply encryption/decryption decorators as needed (config-driven)
if CPUJobConfig.enable_encryption_incoming:
    decorated_func = encrypt_incoming(decorated_func)
if CPUJobConfig.enable_encryption_exporting:
    decorated_func = decrypt_outgoing(decorated_func)
```

- Place `circuit` before `retry_decorator` so the circuit breaker can open after repeated failures and block retries until recovery.
- Use for expensive or error-prone CPU jobs, or when calling unreliable external dependencies.

---

## Encryption Best Practices for CPU-Intensive Endpoints

If the CPU job payload or result contains sensitive data, add `with_encrypted_parameters` as the last decorator in your stack. This is especially important for jobs handling user secrets, tokens, or regulated info.

**Example:**
```python
CopyInsert
decorated_func = trace_function(...)(cpu_job_logic)
decorated_func = track_errors(decorated_func)
decorated_func = measure_performance(...)(decorated_func)
decorated_func = with_encrypted_parameters(decorated_func)  # <-- Encryption last!
```

---

```python
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.db_utils.security.mfa import get_mfa_service, MFAService  # Import for MFA enforcement

# Example usage in route signature:
# mfa_service: MFAService = Depends(get_mfa_service),  # Enforce MFA if required by config

from app.core.db_utils.credits.credits import call_function_with_credits
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from prometheus_client import Histogram  # Prometheus metrics
from circuitbreaker import circuit
from app.core.db_utils.decorators import (
    
    with_encrypted_parameters,
   
)
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.pulsar.decorators import pulsar_task
from app.core.valkey_core.cache import get_or_set_cache
import logging

class JobRequest(BaseModel):
    job_type: str
    payload: dict
    idempotency_key: str
    mfa_code: str

router = APIRouter()

@router.post("/cpu-job")
async def run_cpu_job(
    request: Request,
    job: JobRequest,
    verified=Depends(get_verified_user),
    db=Depends(get_db_client),
    user=Depends(require_scope("run:cpu_jobs")),
    roles=Depends(roles_required(["cpu_job_runner"])),
    ip_ok=Depends(verify_ip_whitelisted),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    # 1. Rate limiting per user
    key = f"cpu_job:{verified['user'].id}:{job.job_type}"
    allowed = await is_allowed_token_bucket(key, capacity=2, refill_rate=1, interval=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests (rate limit)")

    # 2. MFA verification (required)
    await mfa_service.verify_mfa(verified['user'].id, job.mfa_code)

    # 3. Credits check
    await call_function_with_credits(verified['user'].id, "cpu_job", required_credits=1)

    # 4. Idempotency cache (avoid duplicate jobs)
    @with_idempotency_cache(key_func=lambda: job.idempotency_key)
    @pulsar_task(
        topic="persistent://public/default/cpu-jobs",
        dlq_topic="persistent://public/default/cpu-jobs-dlq",
        max_retries=2,
        retry_delay=2.0
    )
    async def cpu_job_logic():
        import time
        from prometheus_client import Histogram
        CPU_JOB_LATENCY = Histogram('cpu_job_latency_seconds', 'CPU job latency (seconds)', ['job_type'])
        start = time.perf_counter()
        try:
            # Simulate CPU work
            result = heavy_cpu_function(job.payload)
        except Exception as exc:
            logging.error(f"CPU job error: {exc}", extra={"user_id": verified['user'].id})
            raise HTTPException(status_code=500, detail="Job failed")
        finally:
            duration = time.perf_counter() - start
            CPU_JOB_LATENCY.labels(job_type=job.job_type).observe(duration)
        return {"result": result, "duration": duration}

    # 5. Decorator stack for observability and error handling
    decorated_func = trace_function(name="cpu_job_logic")(cpu_job_logic)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=500.0, level="warn")(decorated_func)

    return await decorated_func()

def heavy_cpu_function(payload: dict) -> dict:
    # Replace with actual CPU-intensive logic
    import hashlib
    data = str(payload).encode()
    return {"hash": hashlib.sha256(data).hexdigest()}
```

router = APIRouter()
tracer = get_tracer(__name__)

@router.post("/cpu-job")
async def submit_cpu_job(
    request: Request,
    job: JobRequest,
    user=Depends(require_scope("run:cpu_job")),
    roles=Depends(roles_required(["cpu_user"])),
    ip_whitelisted: bool = Depends(verify_ip_whitelisted),  # Enforce IP whitelist
    db=Depends(...),  # Your DB/session dependency
):
    if not ip_whitelisted:
        raise HTTPException(status_code=403, detail="IP address not whitelisted")

    # 1. Rate limiting (Valkey-backed)
    key = f"cpu:job:{user.id}:{job.job_type}"
    allowed = await is_allowed_token_bucket(key, capacity=2, refill_rate=1, interval=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (token bucket)")

    # 2. Idempotency check (Valkey or DB)
    # Example: if await valkey.exists(job.idempotency_key): return cached_result

    # 3. Credits enforcement (deduct before job submission)
    @trace_function(name="endpoint_logic")  # * Distributed tracing for job logic
    @measure_performance(threshold_ms=200.0, level="warn")  # * Prometheus/OpenTelemetry performance metrics
    @track_errors  # * Centralized error tracking
    async def endpoint_logic(request, user):
        import time
        start_time = time.perf_counter()
        try:
            # Enqueue or run the CPU-intensive job here
            # Save result with idempotency_key for deduplication
            return {"status": "submitted", "job_id": "..."}
        except Exception as exc:
            logging.error(f"CPU job error: {exc}")
            raise HTTPException(status_code=500, detail="Job submission error")
        finally:
            duration = (time.perf_counter() - start_time) * 1000  # ms
            cpu_job_latency_histogram.observe(duration)  # Record job latency in Prometheus

    return await call_function_with_credits(
        func=endpoint_logic,
        request=request,
        credit_type="ai",  # or "leads", "skiptrace"
        db=db,
        current_user=user,
        credit_amount=1  # or dynamic
    )

# Note: These decorators are compatible with both sync and async functions. Use arguments as needed for your observability and performance requirements.

```
- This pattern ensures all CPU jobs are strictly rate-limited, credit-enforced, RBAC-secured, monitored, and deduplicated.
- Log all exceptions and rejected jobs with structured, sanitized logs.
- Expose job status and errors via a polling endpoint or webhook.
- Provide clear user-facing error messages for quota/rate/validation failures.

## 8. Example: CPU-Intensive Endpoint Pattern (Pulsar/Valkey)
```python
from fastapi import APIRouter, Depends, HTTPException
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.valkey_core.limiter import token_bucket_limiter
from app.core.db_utils.credits import require_credits
from app.core.pulsar_utils import publish_job_to_pulsar
# or: from app.core.valkey_utils import enqueue_job_to_valkey

router = APIRouter()

@router.post("/heavy-calc")
@token_bucket_limiter(max_tokens=2, refill_rate=1)
@require_credits(amount=10)
async def submit_heavy_job(
    payload: HeavyJobInput,
    user=Depends(require_scope("run:cpu_job")),
    roles=Depends(roles_required(["cpu_user"]))
):
    job_id = await publish_job_to_pulsar(payload, user.id)
    # or: job_id = await enqueue_job_to_valkey(payload, user.id)
    return {"job_id": job_id, "status": "queued"}
```
- Use `publish_job_to_pulsar` for durability, replay, and multi-worker fan-out.
- Use `enqueue_job_to_valkey` for fast, lightweight queueing or hybrid patterns.
- Workers should consume from Pulsar or Valkey, execute the CPU-bound task, and update job status/results for polling/webhooks.

## 9. References
- [Celery Worker Best Practices](../../workers/celery.md)
- [Rate Limiting](../../api/limiting/valkey_limiting.md)
- [Credits System](../../credits/credits.md)
- [Prometheus Metrics](../../monitoring/metrics_with_prometheus.md)
- [Idempotency Patterns](../../valkey/valkey.md)

---

*Follow these best practices to ensure CPU-intensive endpoints are safe, scalable, and user-friendly. Last updated: 2025-05-13.*
