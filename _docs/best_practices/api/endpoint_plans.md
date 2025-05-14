# Endpoint Integration Plans: FastAPI + db_utils

This document provides step-by-step plans and code patterns for integrating each type of endpoint (DB, I/O, CPU-intensive) with FastAPI using project best practices. Each plan includes permission checks, dependency injection, and relevant utilities.

---

## 1. Database (DB) Endpoint Plan
**Goal:** Secure, observable, efficient, and cache-optimized DB access via FastAPI route.

**Steps:**
1. Define Pydantic input/output models for strict validation.
2. Use async DB session dependency from connection pool.
3. Add permission checks using `require_scope` and `roles_required`.
4. Apply query optimization (caching, retries, circuit breaker) via `QueryOptimizer` or decorators.
5. Use Valkey/Redis caching for expensive or frequently accessed queries (`get_or_set_cache`).
6. Add Prometheus metrics and OpenTelemetry tracing.
7. Return clear, actionable errors.

**Secure Input Handling:**
```python
from pydantic import BaseModel

class RecordQuery(BaseModel):
    id: int
    filter: str | None = None
```
- Use ORM query builders or parameterized queries:
```python
# BAD: f"SELECT * FROM records WHERE name = '{user_input}'"
# GOOD:
result = await db.execute(select(MyModel).where(MyModel.name == user_input))
```

**Rate Limiting & Quotas:**
```python
from app.core.valkey_core.limiter import token_bucket_limiter
from app.core.db_utils.credits import require_credits

@router.get("/records/{record_id}")
@token_bucket(max_tokens=5, refill_rate=1)  # Token Bucket (burst control)
# or use:
# @debounce(interval=2)  # Debounce (no repeated calls within interval)
# @fixed_window(limit=10, window=60)  # Fixed window (simple per-period limit)
# @sliding_window(limit=10, window=60)  # Sliding window (smoothed per-period limit)
# @throttle(rate=2, per=1)  # Throttle (max N per period, smoother than fixed window)

@require_credits(amount=2)
async def get_record(...):
    ...
```

**Error Handling:**
```python
import logging
from fastapi import HTTPException

class MyDbException(Exception):
    pass

try:
    result = await some_db_call()
except MyDbException as exc:
    logging.error(f"DB error: {exc}")
    raise HTTPException(status_code=500, detail="Database error")
```

**Monitoring & Metrics:**
```python
from app.core.monitoring.prometheus import record_db_latency
from opentelemetry.trace import get_tracer

tracer = get_tracer(__name__)

async with record_db_latency("get_record"):
    with tracer.start_as_current_span("db_query"):
        result = await db_call()
```

**Example:**
```python
from fastapi import APIRouter, Depends, HTTPException
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.db_utils.db_optimizations import QueryOptimizer
from app.core.db_utils.db_selector import get_db_client
from app.core.valkey_core.cache import get_or_set_cache
from app.core.valkey_core.limiter import token_bucket_limiter
from app.core.db_utils.credits import require_credits
from app.core.monitoring.prometheus import record_db_latency
from opentelemetry.trace import get_tracer

router = APIRouter()
tracer = get_tracer(__name__)

@router.get("/records/{record_id}")
@token_bucket(max_tokens=5, refill_rate=1)  # Token Bucket (burst control)
# or use:
# @debounce(interval=2)  # Debounce (no repeated calls within interval)
# @fixed_window(limit=10, window=60)  # Fixed window (simple per-period limit)
# @sliding_window(limit=10, window=60)  # Sliding window (smoothed per-period limit)
# @throttle(rate=2, per=1)  # Throttle (max N per period, smoother than fixed window)

@require_credits(amount=2)
async def get_record(
    record_id: int,
    user=Depends(require_scope("read:records")),
    roles=Depends(roles_required(["db_reader"])),
    db=Depends(get_db_client)
):
    cache_key = f"record:{record_id}"
    tracer = get_tracer(__name__)
    async def fetch_record():
        # Monitoring & tracing for DB call
        with tracer.start_as_current_span("db_query"):
            async with record_db_latency("get_record"):
                try:
                    # Query optimization (caching, circuit breaker, etc. inside this call)
                    return await QueryOptimizer.optimized_query(MyModel, {"id": record_id}, db)
                except Exception as exc:
                    logging.error(f"DB error: {exc}")
                    raise HTTPException(status_code=500, detail="Database error")
    result = await get_or_set_cache(cache_key, fetch_record, expire=300)  # 5 min cache
    if not result:
        raise HTTPException(status_code=404, detail="Record not found")
    return result
```
- Use `get_or_set_cache` to cache DB results for frequently accessed or expensive queries.
- Invalidate/update cache on relevant data changes.
- All permission, optimization, and error handling best practices remain in place.

---

## 2. I/O (External API, File, Network) Endpoint Plan
**Goal:** Robust, rate-limited, and observable integration with external systems.

**Steps:**
1. Define Pydantic models for input/output.
2. Use permission checks (`require_scope`, `roles_required`).
3. Apply rate limiting (FastAPI Limiter, Valkey limiter).
4. Add retry/circuit breaker decorators for flaky I/O.
5. Use Prometheus metrics and tracing.
6. Handle errors with log-and-raise patterns.

**Example:**
```python
from fastapi import APIRouter, Depends, HTTPException
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.valkey_core.limiter import token_bucket_limiter
from app.core.db_utils.retry import retry_decorator

router = APIRouter()

@router.get("/external-data")
@token_bucket(max_tokens=5, refill_rate=1)  # Token Bucket (burst control)
# or use:
# @debounce(interval=2)  # Debounce (no repeated calls within interval)
# @fixed_window(limit=10, window=60)  # Fixed window (simple per-period limit)
# @sliding_window(limit=10, window=60)  # Sliding window (smoothed per-period limit)
# @throttle(rate=2, per=1)  # Throttle (max N per period, smoother than fixed window)

@retry_decorator(max_attempts=3)
async def fetch_external_data(
    query: str,
    user=Depends(require_scope("read:external")),
    roles=Depends(roles_required(["io_user"]))
):
    # Call external API or I/O
    ...
```

---

## 3. CPU-Intensive Endpoint Plan
**Goal:** Offload heavy computation, enforce quotas, and ensure secure access.

**Steps:**
1. Define strict Pydantic input/output models.
2. Require credits/quota before job submission.
3. Use permission checks (`require_scope`, `roles_required`).
4. Apply strict rate limiting (token bucket, global concurrency if needed).
5. Publish job to Pulsar or Valkey queue (not in API process).
6. Return a job/task ID for polling/webhook.
7. Use Prometheus metrics and expose job status endpoints.

**Example:**
```python
from fastapi import APIRouter, Depends, HTTPException
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.valkey_core.limiter import token_bucket_limiter
from app.core.db_utils.credits import require_credits
from app.core.pulsar_utils import publish_job_to_pulsar

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
    return {"job_id": job_id, "status": "queued"}
```

---

*Use these plans as templates for production-grade FastAPI endpoints. Always integrate permission checks, dependency injection, and observability from the start. Last updated: 2025-05-13.*
