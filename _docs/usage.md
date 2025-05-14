# Database Utilities Usage Guide (Production-Grade)

This guide explains how to use all `db_utils` modules and best practices for robust, scalable, and secure API/database operations. It integrates Prometheus, OpenTelemetry, Pulsar, Valkey, async Supabase, security, rate limiting, caching, credits, monitoring, circuit breaker, RBAC, error handling, and idempotency. See the [flow chart](./flow_chart.mermaid) for a visual overview.

---

## 1. Authentication & Authorization
- **OAuth Scopes & RBAC**: Use `require_scope`, `roles_required`, and async Supabase patterns for secure, non-blocking user validation.
- **References**: [`fast-api-oauth_scopes.md`](best_practices/api/auth/fast-api-oauth_scopes.md), [`role_and_scope_dependencies.md`](best_practices/api/auth/role_and_scope_dependencies.md)
- **Example:**
    ```python
    from app.core.db_utils.security.oauth_scope import require_scope
    @app.get("/secure-data")
    async def secure_data(user=Depends(require_scope("read:data"))):
        ...
    ```

## 2. Rate Limiting & Abuse Protection
- **FastAPI Limiter**: Per-route limits for DDoS/abuse defense.
- **Valkey Algorithms**: Use sliding window, token bucket, debounce, throttle for custom logic.
- **References**: [`fast-api-limiter.md`](best_practices/api/limiting/fast-api-limiter.md), [`valkey_limiting.md`](best_practices/api/limiting/valkey_limiting.md)

## 3. Caching
- **Valkey Cache**: Use `get_or_set_cache` for API/DB/external results. Support batch warming, stale cache, and all major eviction strategies.
- **References**: [`valkey_cache.md`](best_practices/caching/valkey_cache.md)

## 4. Credits & Quotas
- **Credits System**: Estimate and deduct credits for resource-intensive endpoints. Return 402/429 if quota exceeded.
- **References**: [`credits.md`](best_practices/credits/credits.md)

## 5. Database Access & Optimization
- **Selector & Pooling**: Use `get_db_client()` and `ConnectionPool` for async, multi-cloud DB access.
- **Optimizations**: Apply retries, caching, circuit breaker, and query prefetching via `db_optimizations.py` and `decorators.py`.
- **References**: [`db_selector.md`](best_practices/db/db_selector.md), [`db_optimizations_usage.md`](best_practices/db/db_optimizations_usage.md)

## 6. Monitoring, Metrics, and Tracing
- **Prometheus**: Track API calls, DB latency, error rates. Use config-driven metric constants and context managers.
- **OpenTelemetry**: Add distributed tracing for async flows.
- **References**: [`metrics_with_prometheus.md`](best_practices/monitoring/metrics_with_prometheus.md), [`tracing_with_opentelemetry.md`](best_practices/monitoring/tracing_with_opentelemetry.md)
- **Example:**
    ```python
    from prometheus_client import Histogram
    LATENCY = Histogram('api_latency_seconds', 'API call latency', ['endpoint'])
    with LATENCY.labels(endpoint="/secure-data").time():
        ...
    ```

## 7. Pulsar/Event Streaming
- **Async Valkey<->Pulsar**: Use async workers for forwarding, replay, buffering, and hybrid fan-out.
- **RBAC & Circuit Breaker**: Enforce role checks and use retry/circuit breaker decorators on all worker/event tasks.
- **References**: [`pulsar.md`](best_practices/pulsar/pulsar.md), [`valkey-pulsar.md`](best_practices/valkey/valkey-pulsar.md)

## 8. Security & Input Validation
- **Token Management**: Secure JWT/session handling, brute force and replay protection, Pydantic models for all inputs.
- **Logging & MFA**: Secure logging and MFA enforcement.
- **References**: [`authentication_and_token_management.md`](best_practices/security/authentication_and_token_management.md), [`input_validation_middleware.md`](best_practices/security/input_validation_middleware.md)

## 9. Error Handling, Idempotency, and Observability
- **Custom Exceptions**: Use log-and-raise patterns for all API errors.
- **Idempotency**: Use Valkey for idempotency keys and deduplication.
- **Structured Logging**: All endpoints and workers log structured events and expose metrics.

## 10. Example: Secure, Observable, Rate-Limited Endpoint
```python
from fastapi import APIRouter, Depends, HTTPException
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.valkey_core.cache.decorators import get_or_set_cache
from prometheus_client import Histogram

router = APIRouter()

@router.get("/user/{user_id}")
@get_or_set_cache(key_fn=lambda user_id: f"user:{user_id}", ttl=60)
async def get_user_profile(user_id: str, user=Depends(require_scope("read:user"))):
    # Business logic here
    ...
```

## 11. References
- See each linked `.md` file above for deep dives, code samples, and advanced patterns.
- [API Auth Best Practices](best_practices/api/auth/fastapi_auth_scope_integration.md)
- [Valkey Worker Patterns](best_practices/valkey/valkey.md)
- [Circuit Breaker/Retry](best_practices/retry/circuit_breaker.md)

---

*This document is your onboarding and daily reference for all API/database integration patterns in this project. Last updated: 2025-05-13.*

Use `get_db_url()` to construct your DB URL from environment variables. Pool settings are tunable for production.

```python
from app.core.db_utils.db_config import get_db_url
url = get_db_url()
```

---

## 2. Connection Pooling (`pool.py`)
Use `ConnectionPool` for async-safe pooling, circuit breaker, and Prometheus metrics.

```python
from app.core.db_utils.pool import ConnectionPool
pool = ConnectionPool()
async with pool.session_scope() as session:
    result = await session.execute(...)
```

---

## 3. DB Client Selection (`db_selector.py`)
Selects the correct DB client/session based on environment (Supabase or Postgres).

```python
from app.core.db_utils.db_selector import get_db_client
client = get_db_client()
```

---

## 4. Query Optimization (`db_optimizations.py`)
For retries, caching, circuit breaker, metrics, and query prefetching:

```python
from app.core.db_utils.db_optimizations import QueryOptimizer
result = QueryOptimizer.optimize_single_object_query(MyModel, query_params, db_session)
```

---

## 5. Decorators (`decorators.py`)

Core decorators: `@retry_decorator`, `@with_engine_connection`, `@with_query_optimization`, `@with_pool_metrics`, `@with_secure_environment`, `@with_encrypted_parameters`.

```python
from app.core.db_utils.decorators import (
    retry_decorator, with_engine_connection, with_query_optimization,
    with_pool_metrics, with_secure_environment, with_encrypted_parameters
)
```

---

## 6. Encryption (`encryption.py`)
Use `DataEncryptor` for Fernet-based encryption/decryption, key rotation, and metrics.

```python
from app.core.db_utils.encryption import DataEncryptor
encryptor = DataEncryptor()
ciphertext = encryptor.encrypt("my sensitive data")
plaintext = encryptor.decrypt(ciphertext)
```

---

## 7. Secure Environment (`sensitive.py`)
Securely load .env and sensitive config files before any DB or encryption operation.

```python
from app.core.db_utils.sensitive import load_environment_files
load_environment_files()
```

---

## 8. Visual Flow
See [flow_chart.mermaid](./flow_chart.mermaid) for a visual overview: environment loading, client selection, pooling, decorator stack, query execution, caching, error handling, and metrics.

---

*Guide updated 2025-05-13. For advanced usage, see inline code comments and the flow chart.*

- Use `get_db_url()` to construct your DB URL from environment variables.
- Pool settings (size, overflow, recycle, timeout) are production-ready and can be tuned via environment variables.

**Example:**
```python
from app.core.db_utils.db_config import get_db_url
url = get_db_url()
```

---

## 2. Query Optimization (`db_optimizations.py`)
- Use `QueryOptimizer` for production features: circuit breaker, retries, logging, Prometheus metrics, Redis caching, and query prefetching.
- Use `OptimizedQuerySetMixin` to add query optimization to your FastAPI dependencies.

**Example:**
```python
from app.core.db_utils.db_optimizations import QueryOptimizer
# MyModel = SQLAlchemy model, query_params = dict of query filters, db_session = async session
result = await QueryOptimizer.optimized_query(MyModel, query_params, db_session)
```

**FastAPI Dependency Example:**
```python
from app.core.db_utils.db_optimizations import OptimizedQuerySetMixin
from fastapi import Depends

class MyQuerySet(OptimizedQuerySetMixin, MyModel):
    ...

def get_queryset(db=Depends(get_db)):
    return MyQuerySet(db)
```

---

## 3. DB Client Selection (`db_selector.py`)
- Dynamically selects the correct DB client/session based on environment (supports Supabase and Postgres).

**Example:**
```python
from app.core.db_utils.db_selector import get_db_client
client = get_db_client()
```

---

## 4. Decorators (`decorators.py`)

### Key Decorators:
- `@retry_decorator`: Retries DB ops on transient errors (configurable exceptions and attempts).
- `@with_engine_connection`: Manages DB engine/connection lifecycle.
- `@with_query_optimization`: Applies query optimization (caching, circuit breaker, metrics).
- `@with_pool_metrics`: Tracks pool metrics and health.
- `@with_secure_environment`: Ensures `.env`/environment is loaded before DB ops.
- `@with_encrypted_parameters`: Encrypts/decrypts sensitive parameters automatically.

**Example Usage:**
```python
from app.core.db_utils.decorators import (
    retry_decorator, with_engine_connection, with_query_optimization,
    with_pool_metrics, with_secure_environment, with_encrypted_parameters
)

# Typical order: Load environment first, then get a connection, then apply optimizations/retries to the operation using that connection.
@with_secure_environment
@with_engine_connection
@retry_decorator(max_retries=5)
@with_query_optimization
@with_pool_metrics
@with_encrypted_parameters
async def fetch_sensitive_user_data(...):
    # Your DB logic here
    pass
```

---

## 5. Encryption (`encryption.py`)
- Use `DataEncryptor` for Fernet-based encryption/decryption, key rotation, and metrics.
- Used automatically by `@with_encrypted_parameters`.
- **Key Source:** Uses the `SECRET_KEY` from `settings` by default for encryption.

**Example:**
```python
from app.core.db_utils.encryption import DataEncryptor
cipher = DataEncryptor()
encrypted = cipher.encrypt_data("mysecret")
decrypted = cipher.decrypt_data(encrypted)
```

---

## 6. Health Checks (`health_router.py`)
- FastAPI router exposes `/live` and `/ready` endpoints for Kubernetes liveness/readiness.
- Probes DB and Redis cache health.

---

## 7. Connection Pooling (`pool.py`)
- Implements async connection pool with circuit breaker, Prometheus metrics, and health validation.
- Use `ConnectionPool` for robust, monitored DB sessions.
- **Note:** Developers typically do not interact with `ConnectionPool` directly; it is primarily managed internally by decorators like `@with_engine_connection`.

---

## 8. Secure Environment Loading (`sensitive.py`)
- Loads environment variables from `.env` if present, ensuring sensitive config is available before DB ops.

**Example:**
```python
from app.core.db_utils.sensitive import load_environment_files
load_environment_files()
```

---

## 9. Best Practices
- Always use `get_password_hash` for storing user passwords.
- Use `verify_password` to check passwords, which automatically rate limits attempts.
- Use `create_access_token` for issuing JWTs; this is also rate limited to prevent abuse.
- Handle `HTTPException` for rate limit errors in your API endpoints.
- Store `SECRET_KEY` securely and rotate periodically.
- Tune rate limits for your threat model and user base.
- **Database Transactions:** Use database transactions (`async with session.begin():`) for operations that need atomicity. While decorators may handle sessions, explicit transaction management is still recommended for critical business logic.

For more details, see the code and docstrings in each file.