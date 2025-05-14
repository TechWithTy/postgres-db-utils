# Endpoint Integration Plans: FastAPI + db_utils

This document outlines the unified, production-grade approach for integrating endpoints (DB, I/O, CPU) with FastAPI using config-driven workers and policy enforcement. All endpoints now use centralized JobConfig and enforce_all_policies for DRY, scalable, and testable best practices.

---

## 🟢 Unified Usage Pattern (All Endpoint Types)
**Best Practice:**
- Define a `JobConfig` with per-endpoint settings for security, rate limiting, caching, circuit breaker, tracing, metrics, and encryption.
- Instantiate `config = JobConfig()` at the top of your worker file.
- For each route, attach `enforce_all_policies("endpoint_name", config)` as a dependency.
- Use the `api_worker(config)` decorator to wrap the handler for unified enforcement, logging, and observability.

**Example:**
```python
from fastapi import APIRouter, Request, Depends
from pydantic import BaseModel
from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.pipelines.utils.policies import enforce_all_policies
from app.core.db_utils._docs.best_practices.api.pipelines.worker import api_worker

config = JobConfig()
router = APIRouter()
my_endpoint_policy = enforce_all_policies("my_endpoint", config)

class MyInput(BaseModel):
    ...
class MyOutput(BaseModel):
    ...

@router.post("/my-endpoint", response_model=MyOutput, dependencies=[my_endpoint_policy])
@api_worker(config)
async def my_endpoint(...):
    ...
```
- All policy logic (rate limiting, cache, circuit breaker, security, etc.) is handled via config and enforced by `enforce_all_policies`.
- No more direct decorator usage for these concerns—**just update your config!**

---

## 1. Database (DB) Endpoint Plan
**Goal:** Secure, observable, efficient, and cache-optimized DB access via FastAPI route.

**Steps:**
1. Define strict Pydantic input/output models.
2. Use async DB session dependency.
3. Add permission checks via config (JobConfig.security, roles_required, require_scope).
4. Attach `enforce_all_policies("db_worker_endpoint", config)` to the route.
5. Use `api_worker(config)` for unified logging, tracing, and error handling.
6. All caching, rate limiting, and circuit breaking are now handled by config, not direct decorators.

**Example:**
```python
config = JobConfig()
db_worker_policy = enforce_all_policies("db_worker_endpoint", config)

@router.post("/db_worker_endpoint", response_model=UserInDB, dependencies=[db_worker_policy])
@api_worker(config)
async def db_worker_endpoint(...):
    ...
```

---

## 2. I/O (External API, File, Network) Endpoint Plan
**Goal:** Robust, rate-limited, and observable integration with external systems.

**Steps:**
1. Define strict Pydantic models for input/output.
2. Add permission checks via config.
3. Attach `enforce_all_policies("io_endpoint", config)` as a dependency.
4. Use `api_worker(config)` for retries, circuit breaker, tracing, and error handling.

**Example:**
```python
config = JobConfig()
io_policy = enforce_all_policies("io_endpoint", config)

@router.get("/external-data", dependencies=[io_policy])
@api_worker(config)
async def fetch_external_data(...):
    ...
```

---

## 3. CPU-Intensive Endpoint Plan
**Goal:** Offload heavy computation, enforce quotas, and ensure secure access.

**Steps:**
1. Define strict Pydantic input/output models.
2. Require credits/quota via config.
3. Add permission checks via config.
4. Attach `enforce_all_policies("cpu_worker_endpoint", config)` as a dependency.
5. Use `api_worker(config)` for unified best practices.

**Example:**
```python
config = JobConfig()
cpu_worker_policy = enforce_all_policies("cpu_worker_endpoint", config)

@router.post("/cpu_worker_endpoint", dependencies=[cpu_worker_policy])
@api_worker(config)
async def submit_heavy_job(...):
    ...
```

---

**Key Points:**
- All endpoint logic for security, rate limiting, caching, circuit breaker, tracing, metrics, and encryption is now config-driven.
- No direct decorator usage for these concerns—**just update JobConfig and use enforce_all_policies!**
- This pattern is DRY, scalable, and testable.
- To add a new policy, update JobConfig and enforcement logic in policies.py.
- All legacy/deprecated patterns (direct decorator usage for rate limiting, caching, etc.) have been removed.

_Last updated: 2025-05-13_
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

---

## 🗺️ Unified Endpoint Flow (Mermaid)



**Legend:**
- All policy checks (security, rate limiting, idempotency, tracing, etc.) are enforced via `enforce_all_policies` and `JobConfig`.
- Only if all policies pass does the request proceed to the worker logic.
- All logging, tracing, and error handling are unified in the `api_worker` decorator.
- Response is returned to the client.

