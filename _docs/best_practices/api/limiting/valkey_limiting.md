# Valkey-Based Rate Limiting: Best Practices & Integration

This guide documents how to use Valkey (Redis-compatible) for advanced rate limiting in your FastAPI APIs, including sliding window, service/user limits, decorators, and retry logic. Use this in addition to FastAPI Limiter for robust, production-grade API protection.

---

## 1. Why Use Custom Valkey Limiting?
- FastAPI Limiter is great for basic per-route limits.
- Valkey-based logic lets you implement advanced, business-driven rules (multi-tenant, per-service, burst/billing, etc.).
- Enables DRY, SOLID, and CI/CD best practices for scalable, testable, and observable rate limiting.

---

## 2. Supported Valkey Rate Limiting Algorithms

### 2.1 Debounce (debounce.py)
Allow an event only after a period of inactivity. Useful for deduplication, UI spam protection, and notification throttling.
```python
from app.core.valkey_core.algorithims.rate_limit.debounce import is_allowed_debounce

allowed = await is_allowed_debounce(key, interval=30)
if allowed:
    # Proceed with action
```

### 2.2 Fixed Window (fixed_window.py)
Allow up to N events per fixed window (e.g., 100/min). Simple, but can be bursty at window edges.
```python
from app.core.valkey_core.algorithims.rate_limit.fixed_window import is_allowed_fixed_window

allowed = await is_allowed_fixed_window(key, limit=100, window=60)
```

### 2.3 Sliding Window (sliding_window.py)
Smooths out bursts, fairer than fixed window. Uses sorted sets for accurate rolling limits.
```python
from app.core.valkey_core.limiting.rate_limit import check_rate_limit

allowed = await check_rate_limit(client, key, limit=100, window=60)
```

### 2.4 Token Bucket (token_bucket.py)
Allows bursts up to a max, then refills tokens over time. Ideal for premium/burst-tolerant APIs.
```python
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket

allowed = await is_allowed_token_bucket(key, max_tokens=10, refill_rate=1)
```

### 2.5 Throttle (throttle.py)
Enforce a minimum interval between events. Useful for login attempts, payments, or anti-brute-force.
```python
from app.core.valkey_core.algorithims.rate_limit.throttle import is_allowed_throttle

allowed = await is_allowed_throttle(key, interval=60)
```

---

## 3. Verify and Limit Decorators

```python
from app.core.valkey_core.limiting.decorators import verify_and_limit

@verify_and_limit(limit=10, window=60, key_func=custom_key)
async def sensitive_action(...):
    ...
```
- Decorator enforces limits on any async function (route, task, etc.).
- Use `key_func` to customize per-user, per-IP, or per-service keys.

---

## 4. Service & User Rate Limiting

```python
from app.core.valkey_core.limiting.rate_limit import service_rate_limit

@app.get("/service-endpoint")
@service_rate_limit(limit=1000, window=3600)
async def service_api(...):
    ...
```
- Use for API keys, service-to-service, or privileged user flows.

---

## 5. Retry Logic for Transient Failures

```python
from app.core.valkey_core.limiting.retry import retry_with_backoff

@retry_with_backoff(max_attempts=3, base_delay=0.5)
async def call_external_api(...):
    ...
```
- Use for external APIs or Valkey operations that may fail transiently.
- Ensures resilience and graceful degradation.

---

## 6. Best Practices
- Always combine FastAPI Limiter (initial defense) with Valkey-based logic (business rules).
- Use structured logging and Prometheus metrics for all rate limiting events.
- Store rate limit keys with clear prefixes: `rate:user:{id}`, `rate:service:{service}`.
- Handle Valkey/Redis outages gracefully (fail closed, alert, or degrade safely).
- Write tests for edge cases and race conditions.

---

*See also: `when_to_use.md` for algorithm selection, and `valkey.md` for Valkey connection/configuration best practices.*

*Last updated: 2025-05-13*
