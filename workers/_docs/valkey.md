# Valkey Worker Setup Guide: Celery, Pub/Sub, and Polling

This guide walks you through setting up a production-grade Valkey-backed worker system using Celery, Redis/Valkey pub/sub, and polling patterns. It is intended for teams migrating to, or scaling with, Valkey as a resilient, observable, and high-performance backend for distributed task processing.

---

## 1. Overview

Valkey is a drop-in Redis alternative with enhanced resilience and cloud-native features. When combined with Celery, it powers robust distributed task queues and pub/sub event streams.

**Architecture Components:**
- **Celery**: Distributed task queue for Python
- **Valkey**: Fast, resilient Redis-compatible backend
- **Pub/Sub**: Real-time event delivery between services
- **Polling**: Fallback or hybrid pattern for event consumption

---

## 2. Prerequisites
- Python 3.10+
- Celery 5.x
- Valkey server (standalone or cluster)
- [redis-py](https://pypi.org/project/redis/) or [valkey-py](https://github.com/valkey-io/valkey-py) client
- Properly configured `ValkeyConfig` (see [usage.md](./usage.md))

---

## 3. Worker Setup

### a. Celery Configuration
```python
from celery import Celery

app = Celery(
    'myapp',
    broker='redis://VALKEY_HOST:VALKEY_PORT/0',
    backend='redis://VALKEY_HOST:VALKEY_PORT/1',
)

# Optional: Use Valkey-specific options via ValkeyConfig
def configure_valkey(app):
    app.conf.broker_transport_options = {
        'retry_on_timeout': True,
        'max_retries': 3,  # or from VAPI_RETRY_ATTEMPTS
        'socket_keepalive': True,
    }

configure_valkey(app)
```

### b. Pub/Sub Example
```python
import redis  # or valkey

r = redis.Redis(host='VALKEY_HOST', port=VALKEY_PORT)
pubsub = r.pubsub()
pubsub.subscribe('events')

for message in pubsub.listen():
    if message['type'] == 'message':
        # Process event
        print(f"Received: {message['data']}")
```

### c. Polling Pattern
```python
import time

def poll_for_events():
    while True:
        events = r.lrange('event_queue', 0, -1)
        for event in events:
            # Process event
            pass
        time.sleep(POLL_INTERVAL)
```

---

## 4. Valkey Worker Best Practices

This section outlines production-ready patterns for building Valkey-backed workers, inspired by best practices from Pulsar and main worker implementations.

### Core Principles
- **Strict Type Safety:** Use Pydantic models for all task payloads/configs.
- **Async/Await:** Prefer async functions for I/O and network-bound tasks.
- **Rate Limiting:** Apply per-IP or per-user rate limiting via a decorator.
- **Circuit Breaking & Retries:** Use exponential backoff and circuit breaker patterns for resiliency.
- **Caching & Idempotency:** Leverage Valkey/Redis for caching and deduplication (idempotency keys, TTL windows).
- **Secure Auth:** Enforce API key, OAuth2, or JWT authentication for all endpoints.
- **Observability:** Integrate structured logging and Prometheus metrics.
- **Config-Driven:** All operational parameters (timeouts, retries, limits) should be environment/config-driven.
- **Robust Error Handling:** Use custom exception types and log/raise patterns for API errors.

### Example: Best-Practice Valkey Worker Registration
```python
from typing import Any, Awaitable, Callable
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from app.core.db_utils.workers._schemas import ValkeyIOTaskConfig
from app.core.redis.decorators import cache as cache_decorator
from app.core.redis.rate_limit import service_rate_limit, verify_and_limit
from app.core.telemetry.decorators import measure_performance, trace_function, track_errors
from app.core.db_utils.workers.utils.index import circuit_breaker_decorator
from app.api.utils.security.log_sanitization import get_secure_logger
from app.core.valkey.client import ValkeyClient

logger = get_secure_logger("app.core.db_utils.workers.valkey")

# Auth schemes
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key")


def run_io_task_with_best_practices_valkey(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: ValkeyIOTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async I/O task as a Valkey-backed worker with best practices: caching, rate limiting, retries, circuit breaker, metrics, and permissions.
    Usage:
        await run_io_task_with_best_practices_valkey(my_func, config=ValkeyIOTaskConfig())(*args, **kwargs)
    """
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    max_retries = config.max_retries
    backoff = config.backoff
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    decorated_func = circuit_breaker_decorator(
        max_attempts=max_retries, wait_base=backoff
    )(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(
            ValkeyClient(),  # swap for RedisClient if needed
            ttl=cache_ttl,
            key_builder=lambda f, *args, **kwargs: (
                f"{f.__module__}.{f.__name__}:{args}:{kwargs}"
            ),
        )(decorated_func)
    if rate_limit is not None and rate_window is not None:
        async def rate_limited_func(*args, **kwargs):
            await verify_and_limit(
                service_rate_limit(
                    limit=rate_limit, window=rate_window, endpoint=endpoint
                )
            )
            return await decorated_func(*args, **kwargs)
        decorated_func = rate_limited_func
    # Optionally add permission checks here
    return decorated_func
```

### Error Handling Pattern
```python
from app.core.db_utils.exceptions.exceptions import APIError, log_and_raise_http_exception

try:
    await my_valkey_worker(*args, **kwargs)
except APIError as exc:
    log_and_raise_http_exception(logger, exc)
```

### Observability & Metrics
- Use `measure_performance`, `trace_function`, and `track_errors` decorators.
- Log all events with context and redact sensitive data.
- Expose Prometheus metrics for worker performance, error rates, and queue depth.

### Idempotency & Deduplication
- Use Valkey/Redis to store recent event IDs or hashes with a TTL to prevent duplicate processing.

### Example: Idempotency Key
```python
valkey = ValkeyClient()
idempotency_key = f"event:{event_id}"
if await valkey.exists(idempotency_key):
    return  # Already processed
await valkey.set(idempotency_key, "1", ex=ttl)
# ... process event ...
```

---

## 5. References & Further Reading
- [Valkey Documentation](https://valkey.io/docs/)
- [Celery Best Practices](https://docs.celeryq.dev/en/stable/userguide/tasks.html)
- [Pulsar Worker Example](../pulsar.py)
- [Redis/Valkey Patterns](https://redis.io/docs/)

---

## 6. TODOs & Enhancements
- Add permission role checks
- Add more advanced circuit breaker and fallback logic
- Expand metrics and logging examples

---

## 7. Resilience & Retry (ValkeyConfig)
Valkey's built-in retry/backoff can be configured via environment variables:
- `VAPI_RETRY_ATTEMPTS=5`
- `VAPI_RETRY_BACKOFF_TYPE=exponential`
- `VAPI_RETRY_BACKOFF_BASE=2`
- `VAPI_RETRY_BACKOFF_CAP=30`

See [usage.md](./usage.md) for details.

---

## 8. Flowchart
See [flowchart.mermaid](./flowchart.mermaid) for a visual overview of the worker event flow: Celery tasks, pub/sub, and polling integration.

---

## 9. Best Practices
- Use Celery for durable, reliable background processing.
- Use Valkey pub/sub for real-time, low-latency event delivery.
- Use polling as a fallback or for legacy integrations.
- Monitor worker health and queue lengths with Prometheus or Valkey metrics.
- Tune retry/backoff for your workload via `ValkeyConfig`.
- Secure your Valkey deployment (TLS, auth, network ACLs).
- Document all custom channels and event formats.

---

## 10. References
- [Valkey Official Docs](https://valkey.io/)
- [Celery Documentation](https://docs.celeryq.dev/en/stable/)
- [Redis-py](https://pypi.org/project/redis/)
- [Valkey-py](https://github.com/valkey-io/valkey-py)
- Your local `_docs/usage.md` and `flowchart.mermaid`

---

## 11. Implementation Progress & Parity Tracking

### Parity with Pulsar Worker Best Practices

| Feature/Pattern                  | Pulsar Implementation | Valkey Implementation | Notes/Status |
|----------------------------------|----------------------|-----------------------|--------------|
| Strict Pydantic Models           | ✅                   | ✅                    |              |
| Async/Await                      | ✅                   | ✅                    |              |
| Rate Limiting                    | ✅                   | ✅                    |              |
| Circuit Breaking                 | ✅ (decorator)       | 🚫 (uses Valkey retry/lock) | Valkey uses distributed lock + retry, not circuit breaker decorator |
| Caching (Redis/Valkey)           | ✅                   | ✅                    |              |
| Cache Key Structure              | ✅ (`_build_user_auth_component`, roles, args/kwargs) | ⚠️ Partial | Improve cache key for user/role context |
| Permission/Role Validation       | ✅                   | ⚠️ Partial            | Add permission checks for Valkey |
| Task Priority/Timeout            | ✅                   | ⚠️ Partial            | Expose in Valkey if needed |
| DLQ/Topic Support                | ✅                   | 🚫                    | Not applicable for Valkey |
| Observability (Logging/Metrics)  | ✅                   | ✅                    |              |
| Prometheus Metrics               | ✅                   | ✅                    |              |
| Credit Usage (call_function_with_credits) | ✅         | 🚫                    | To be implemented |
| Error Handling                   | ✅                   | ✅                    |              |
| Idempotency/Deduplication        | ✅                   | ✅                    |              |
| Config-Driven Ops                | ✅                   | ✅                    |              |

#### Legend
- ✅ = Fully implemented
- ⚠️ = Partial, needs improvement
- 🚫 = Not implemented / Not applicable

### Next Steps
- [ ] Implement `call_function_with_credits` logic for Valkey workers (see Pulsar pattern)
- [ ] Enhance cache key builder to match Pulsar (user/role context, args/kwargs)
- [ ] Add permission/role validation decorator for Valkey
- [ ] Expose task priority/timeout if needed
- [ ] Continue to keep Valkey worker patterns in sync with Pulsar best practices

---

## 12. Example: Credits Usage for Valkey
```python
from app.api.utils.credits.credits import call_function_with_credits

async def submit(*args, **kwargs):
    req = kwargs.get("request")
    if credit_type and credit_amount and req is not None:
        credit_amount_local = estimate_credits_for_task(task_func, req)
    else:
        credit_amount_local = credit_amount
    if credit_amount_local > 0:
        logger.info(
            f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}"
        )
        return await call_function_with_credits(
            lambda request, user: decorated_func(*args, **kwargs),
            req,
            credit_type,
            credit_amount=credit_amount_local,
        )
    return await decorated_func(*args, **kwargs)
```

---

## 13. TODOs (Valkey Worker)
- [ ] Integrate credits usage in all Valkey worker registration utilities
- [ ] Add permission/role validation
- [ ] Ensure cache key builder matches Pulsar
- [ ] Add more real-world usage examples

For advanced patterns (e.g., sharding, multi-tenant pub/sub, hybrid polling), see the extended documentation or contact the platform team.

---

## 14. Integrating Apache Pulsar with Valkey + Celery

**When to Use Pulsar:**
- High-throughput event streams (audit logs, analytics, real-time metrics)
- Multi-tenant isolation (per-client topics/namespaces)
- Durable, guaranteed delivery (acknowledgements, DLQ, replay)
- Complex topologies (fan-out, multi-subscription, cursor-based consumption)

**When Not Needed:**
- Low/medium task volume handled by Celery+Valkey
- Simple pub/sub or notification patterns
- If operational simplicity is a priority

**Recommended Approach:**
1. Start with Celery + Valkey for queues and pub/sub.
2. Use Valkey pub/sub for real-time events and polling for fallback.
3. Instrument with Prometheus/OpenTelemetry.
4. If you hit Redis/Valkey limits (memory, connection count, stream size), pilot Pulsar for a high-volume stream.
5. Expand Pulsar only if it provides clear benefits (retention, replay, multi-subscription, etc.).

**Integration Patterns:**
- Use [`valkey-pulsar.py`](./valkey-pulsar.py) for bridging events/queues between Valkey and Pulsar.
- Hybrid publish: send to both Valkey pub/sub and Pulsar for dual-consumer scenarios.
- Replay or migration: subscribe to Pulsar and enqueue to Valkey for worker consumption.

See [`pulsar.md`](./pulsar.md) for more details and operational trade-offs.
