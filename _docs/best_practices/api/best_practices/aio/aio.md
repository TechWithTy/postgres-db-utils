# API Route Best Practices Using Project Utilities

This document outlines production-ready best practices for building API routes using the full suite of db_utils and supporting libraries in this project. Follow these guidelines for secure, observable, scalable, and maintainable FastAPI endpoints.

---

## 1. Authentication & Authorization
- **OAuth Scopes & RBAC**: Use `require_scope`, `roles_required`, and async Supabase patterns for secure, non-blocking user validation.
- **User Role Permissions**: Always enforce user role checks for authorization on all endpoints. Use role-based dependencies (e.g., `roles_required(["admin"])` or `require_scope("read:data")`).
- **References**: [`fast-api-oauth_scopes.md`](../../auth/fast-api-oauth_scopes.md), [`role_and_scope_dependencies.md`](../../auth/role_and_scope_dependencies.md)
- **Example:**
    ```python
    from app.core.db_utils.security.oauth_scope import require_scope
    from app.core.db_utils.security.roles import roles_required
    @app.get("/secure-data")
    async def secure_data(user=Depends(require_scope("read:data")), roles=Depends(roles_required(["admin"]))):
        ...
    ```
- Prefer OAuth scopes for fine-grained access control.

## 2. Rate Limiting & Abuse Protection
- Apply FastAPI Limiter decorators for per-route and per-user limits.

---

## Example: Production-Grade Async IO Endpoint

---

## Circuit Breaker & Retry Logic for IO-Intensive Endpoints

For IO operations that may fail due to transient network errors or unreliable external services, use `circuit` (circuit breaker) and `retry_decorator` to improve reliability and resilience.

**Example:**
```python
CopyInsert
decorated_func = trace_function(...)(io_job_logic)
decorated_func = track_errors(decorated_func)
decorated_func = measure_performance(...)(decorated_func)
decorated_func = circuit(failure_threshold=5, recovery_timeout=30)(decorated_func)
decorated_func = retry_decorator(max_retries=3)(decorated_func)
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing
# Apply encryption/decryption decorators as needed (config-driven)
if IOJobConfig.enable_encryption:
    decorated_func = encrypt_incoming(decorated_func)
if IOJobConfig.enable_decryption:
    decorated_func = decrypt_outgoing(decorated_func)
# * This is the new best practice for all async IO endpoints.
```

- Place `circuit` before `retry_decorator` so the circuit breaker can open after repeated failures and block retries until recovery.
- Use for endpoints that call external APIs, databases, or other unreliable IO resources.

---

## Encryption Best Practices for IO-Intensive Endpoints

If IO operations involve sensitive data (e.g., fetching/writing user files, tokens, PII), add `with_encrypted_parameters` as the last decorator. This ensures that data at rest and in transit is always encrypted/decrypted at the edge of your logic.

**Example:**
```python
CopyInsert
decorated_func = trace_function(...)(io_job_logic)
decorated_func = track_errors(decorated_func)
decorated_func = measure_performance(...)(decorated_func)
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing
# Apply encryption/decryption decorators as needed (config-driven)
if IOJobConfig.enable_encryption:
    decorated_func = encrypt_incoming(decorated_func)
if IOJobConfig.enable_decryption:
    decorated_func = decrypt_outgoing(decorated_func)
# * This is the new best practice for all async IO endpoints.  # <-- Encryption last!
```

---
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.credits.credits import call_function_with_credits
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from app.core.valkey_core.cache.decorators import get_or_set_cache
from app.core.db_utils.security.mfa import get_mfa_service, MFAService  # For MFA enforcement
from app.core.config import IOJobConfig
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from circuitbreaker import circuit
from app.core.db_utils.decorators import retry_decorator
from app.core.pulsar.decorators import pulsar_task
from prometheus_client import Histogram
import logging

class IORequest(BaseModel):
    resource_id: str
    query_params: dict
    idempotency_key: str
    mfa_code: str

router = APIRouter()

@router.post("/io-job")
async def run_io_job(
    request: Request,
    io_req: IORequest,
    verified=Depends(get_verified_user),
    user=Depends(require_scope("run:io_jobs")),
    db=Depends(...),  # Your DB/session dependency
    roles=Depends(roles_required(["io_job_runner"])),
    ip_ok=Depends(verify_ip_whitelisted),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    # Enforce MFA if required by config
    if IOJobConfig.mfa_required:
        await mfa_service.verify_mfa(verified['user'].id, io_req.mfa_code)

    # 1. Rate limiting per user
    key = f"io_job:{verified['user'].id}:{io_req.resource_id}"
    allowed = await is_allowed_token_bucket(key, capacity=5, refill_rate=2, interval=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests (rate limit)")

    # 2. Credits check (enforce per-IO job)
    await call_function_with_credits(verified['user'].id, "io_job", required_credits=1)

    # 3. Idempotency and caching using Valkey
    async def io_job_logic():
        IO_JOB_LATENCY = Histogram('io_job_latency_seconds', 'IO job latency (seconds)', ['resource_id'])
        import time
        start = time.perf_counter()
        try:
            result = await heavy_async_io_function(io_req.resource_id, io_req.query_params)
        except Exception as exc:
            logging.error(f"IO job error: {exc}", extra={"user_id": verified['user'].id})
            raise HTTPException(status_code=500, detail="IO job failed")
        finally:
            duration = time.perf_counter() - start
            IO_JOB_LATENCY.labels(resource_id=io_req.resource_id).observe(duration)
        return {"result": result, "duration": duration}

    decorated_func = trace_function(name="io_job_logic")(io_job_logic)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=500.0, level="warn")(decorated_func)
    decorated_func = circuit(failure_threshold=5, recovery_timeout=30)(decorated_func)
    decorated_func = retry_decorator(max_retries=3)(decorated_func)
    from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing
    if IOJobConfig.enable_encryption:
        decorated_func = encrypt_incoming(decorated_func)
    if IOJobConfig.enable_decryption:
        decorated_func = decrypt_outgoing(decorated_func)

    cache_key = f"io_job:{io_req.idempotency_key}"
    result = await get_or_set_cache(cache_key, lambda: decorated_func(), ttl=1800)

    @pulsar_task(
        topic="persistent://public/default/io-jobs",
        dlq_topic="persistent://public/default/io-jobs-dlq",
        max_retries=2,
        retry_delay=2.0
    )
    async def publish_io_event(event: dict) -> dict:
        return event
    await publish_io_event({"resource_id": io_req.resource_id, "result": result})

    return result

async def heavy_async_io_function(resource_id: str, params: dict) -> dict:
    import asyncio
    await asyncio.sleep(1)
    return {"resource_id": resource_id, "params": params, "data": "fetched_data"}


@router.get("/user/{user_id}")
@get_or_set_cache(key_fn=lambda user_id: f"user:{user_id}", ttl=60)
async def get_user_profile(user_id: str, user=Depends(require_scope("read:user"))):
    # Business logic here
    return {"user_id": user_id, "profile": "user_profile_data"}
```

- Use Valkey-based limiting for advanced patterns (debounce, sliding window, token bucket, throttle).
- Combine both for layered defense against abuse.

## 3. Caching
- Use `get_or_set_cache` for endpoints that return expensive or slow-to-compute results.
- Select the appropriate eviction strategy (LRU, LFU, FIFO, etc.) based on access patterns.
- Warm up caches for dashboards or high-traffic endpoints.

## 4. Credits & Quotas
- Estimate and deduct user credits for resource-intensive endpoints before executing business logic.
- Return 402/429 errors if quota is exceeded.

## 5. Database Access & Optimization
- Use dependency-injected async sessions from a connection pool for all DB access.
- Apply query optimization, retries, and circuit breaker decorators for all performance-critical DB queries.
- Use selector utilities for multi-cloud or dynamic DB backends.

## 6. Monitoring, Metrics, and Tracing
- Track API call counts, latency, and error rates using Prometheus metrics.
- Add OpenTelemetry tracing for distributed async flows.
- Use config-driven metric constants and context managers for consistency.

## 7. Event Streaming (Pulsar)
- Use async Valkey<->Pulsar patterns for event-driven endpoints.
- Apply RBAC and circuit breaker/retry decorators to all event/task handlers.

## 8. Security & Input Validation
- Always use Pydantic models for request/response validation.
- Enforce JWT/session authentication, brute force, and replay protection on all sensitive endpoints.
- Sanitize logs and enforce MFA where required (config-driven, e.g., IOJobConfig.mfa_required).

## 9. Error Handling & Idempotency
- Use custom exception types and log-and-raise patterns for all errors.
- Leverage Valkey for idempotency keys and deduplication.
- Ensure all endpoints log structured events and expose metrics.



## 11. References
- [API Auth Best Practices](fast-api-oauth_scopes.md)
- [Rate Limiting](limiting/fast-api-limiter.md)
- [Caching](../caching/valkey_cache.md)
- [Credits](../credits/credits.md)
- [DB Optimization](../db/db_optimizations_usage.md)
- [Prometheus Metrics](../monitoring/metrics_with_prometheus.md)
- [Tracing](../monitoring/tracing_with_opentelemetry.md)
- [Pulsar Patterns](../pulsar/pulsar.md)
- [Security](../security/security.md)

---

*Follow these patterns to ensure your API routes are secure, efficient, and production-ready. Last updated: 2025-05-13.*
