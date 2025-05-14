# Best Practices for API DB Calls

This guide outlines production-grade patterns for making database calls from API routes using the db_utils suite. Follow these best practices to ensure your endpoints are efficient, safe, and observable.

---

## 1. Use Dependency-Injected Async Sessions
- Always use async session dependencies from a connection pool for DB access.
- Avoid global or static sessions to prevent leaks and concurrency issues.

## 2. Query Optimization
- Use `QueryOptimizer` and optimization decorators for all performance-critical or complex queries.
- Enable caching, retries, and circuit breaker for slow or unreliable queries.
- Prefetch related data to minimize N+1 queries.

## 3. Secure Input Handling
- Validate all query/filter input with Pydantic models:
    ```python
    from pydantic import BaseModel
    class RecordQuery(BaseModel):
        id: int
        filter: str | None = None
    ```
- Sanitize inputs to prevent SQL injection and logic bugs:
    ```python
    # BAD: f"SELECT * FROM records WHERE name = '{user_input}'"
    # GOOD:
    result = await db.execute(select(MyModel).where(MyModel.name == user_input))
    ```

## 4. Rate Limiting & Quotas
- Apply per-user and per-IP rate limits to endpoints that trigger DB queries:
    ```python
    from app.core.valkey_core.limiter import token_bucket_limiter
    @router.get("/records/{record_id}")
    @token_bucket_limiter(max_tokens=5, refill_rate=1)
    async def get_record(...):
        ...
    ```
- Enforce quotas for resource-intensive or high-frequency queries:
    ```python
    from app.core.db_utils.credits import require_credits
    @router.post("/records/query")
    @require_credits(amount=2)
    async def query_records(...):
        ...
    ```

## 5. Caching
- Use Valkey/Redis caching for expensive or frequently repeated queries.
- Invalidate or update cache on relevant data changes.

## 6. Error Handling
- Use custom exception types and log-and-raise patterns for all DB errors:
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
- Return clear, actionable error messages to clients (never raw DB errors).

## 7. Monitoring & Metrics
- Track query latency, error rates, and throughput using Prometheus metrics:
    ```python
    from prometheus_client import Histogram  # Use Prometheus client directly for DB latency
    async with record_db_latency("get_record"):
        result = await db_call()
    ```
- Add OpenTelemetry tracing to capture DB call spans:
    ```python
    from opentelemetry.trace import get_tracer
    tracer = get_tracer(__name__)
    with tracer.start_as_current_span("db_query"):
        result = await db_call()
    ```

## 8. Security & RBAC
- Enforce authentication and RBAC (user role permissions) on all endpoints that access sensitive data.
- Always use role-based dependencies such as `roles_required(["db_reader"])` or `require_scope("read:records")` for fine-grained access control.

## 8a. Circuit Breakers for DB Endpoints
- Use a circuit breaker to protect your database and dependent services from overload and cascading failures.
- Circuit breakers should wrap all critical DB logic, especially for endpoints that call unreliable external services or perform heavy queries.
- Combine with retry logic for maximum resilience: retry transient errors, but open the circuit on persistent failure.

**Example:**
```python
from circuitbreaker import circuit
from app.core.db_utils.decorators import retry_decorator

@retry_decorator(max_retries=3, delay=2.0)
@circuit(failure_threshold=5, recovery_timeout=30, expected_exception=Exception)
async def robust_db_logic(...):
    ...  # Your DB code here
```
- Always put the retry decorator **above** the circuit breaker.
- Tune thresholds to your workload and error patterns.
- See the retry/circuit breaker best practices doc for more advanced usage.

## 9. Example: Optimized, Secure DB Endpoint
```python
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.security.input_validation_middleware import validate_input
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.db_utils.security.oauth import permission_role_guard
from app.core.db_utils.db_optimizations import QueryOptimizer
from app.core.db_utils.db_selector import get_db_client
from app.core.valkey_core.cache import get_or_set_cache
from app.core.db_utils.credits.credits import call_function_with_credits
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.db_utils.decorators import (
    retry_decorator,
    with_encrypted_parameters,
    with_engine_connection,
    with_pool_metrics,
    with_query_optimization,
)
from app.core.pulsar.decorators import pulsar_task
from circuitbreaker import circuit
import logging

router = APIRouter()

class RecordQuery(BaseModel):
    id: int

@router.get("/records/{record_id}")
async def get_record(
    request: Request,
    record_id: int,
    verified=Depends(get_verified_user),
    user=Depends(require_scope("read:records")),
    roles=Depends(roles_required(["db_reader"])),
    db=Depends(get_db_client),
    ip_ok=Depends(verify_ip_whitelisted),
):
    # 1. Rate limiting using verified user id
    key = f"db:records:{verified['user'].id}:{record_id}"
    allowed = await is_allowed_token_bucket(key, capacity=5, refill_rate=1, interval=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Rate limit exceeded (token bucket)")

    # 2. Input validation using Pydantic & middleware
    query = RecordQuery(id=record_id)
    validate_input(query)

    # 3. RBAC and permission guard
    @permission_role_guard(permission_roles=["db_reader"])
    async def protected_logic(request, verified):
        cache_key = f"record:{record_id}"
        from prometheus_client import Histogram
        import time
        DB_LATENCY = Histogram(
    DBEventConfig.metrics.histogram_name,
    DBEventConfig.metrics.histogram_description,
    [DBEventConfig.metrics.histogram_label]
)  # * config-driven metrics
        start_time = time.perf_counter()
        try:
            result = await QueryOptimizer.optimized_query(MyModel, {"id": record_id}, db)
        except Exception as exc:
            logging.error(f"DB error: {exc}", extra={"user_id": verified['user'].id})
            raise HTTPException(status_code=500, detail="Database error")
        finally:
            duration = time.perf_counter() - start_time
            DB_LATENCY.labels(**{DBEventConfig.metrics.histogram_label: DBEventConfig.metrics.fetch_record_label}).observe(duration)  # * config-driven label

        if not result:
            raise HTTPException(status_code=404, detail="Record not found")

        @pulsar_task(
            topic=DBEventConfig.pulsar_labeling.job_topic,
            dlq_topic=DBEventConfig.pulsar_labeling.dlq_topic,
            max_retries=DBEventConfig.pulsar_labeling.max_retries,
            retry_delay=DBEventConfig.pulsar_labeling.retry_delay,
            producer_label=DBEventConfig.pulsar_labeling.producer_label  # * config-driven producer label
        )  # * config-driven Pulsar
        async def publish_db_event(event: dict) -> dict:
            # * Use event_label from config for event payload
            event = {
                DBEventConfig.pulsar_labeling.event_label: record_id,
                "result": result
            }
    return event
            return event
        await publish_db_event({"record_id": record_id, "event": "record_accessed"})
        return result

    # Compose decorators in production order
    decorated_func = trace_function(name="endpoint_logic")(protected_logic)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=150.0, level="warn")(decorated_func)
    decorated_func = with_engine_connection(decorated_func)
    decorated_func = with_query_optimization(decorated_func)
    decorated_func = circuit(failure_threshold=5, recovery_timeout=30, expected_exception=Exception)(decorated_func)
    decorated_func = retry_decorator(max_retries=3)(decorated_func)
    decorated_func = with_pool_metrics(decorated_func)
    decorated_func = with_encrypted_parameters(decorated_func)

    return await decorated_func(request, verified)

# Note: Decorator order matters! Telemetry comes first, then DB/infra, then circuit breaker, then retry, then encryption. This ensures observability, reliability, and security for all DB endpoint logic.
# Tune circuit breaker parameters (failure_threshold, recovery_timeout) to your workload and error patterns.

    return await call_function_with_credits(
        func=endpoint_logic,
        request=request,
        credit_type="ai",  # or "leads", "skiptrace"
        db=db,
        current_user=user,
        credit_amount=2
    )
```

## 10. References
- [DB Optimization](../../../db/db_optimizations_usage.md)
- [Connection Pooling](../../../db/pool_usage.md)
- [Prometheus Metrics](../../../monitoring/metrics_with_prometheus.md)
- [Caching](../../../caching/valkey_cache.md)
- [API Auth](../auth/fast-api-oauth_scopes.md)

---

*Follow these best practices to ensure all DB calls from your API are robust, efficient, and secure. Last updated: 2025-05-13.*
