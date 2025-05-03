# Database Utilities Usage Guide

This guide explains how to use the decorators and core utilities in the `db_utils` module for robust, production-grade database operations.

---

## 1. Configuration (`db_config.py`)
- Centralizes async SQLAlchemy engine and pool settings.
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
result = await QueryOptimizer.optimized_query(MyModel, query_params, db_session)
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

---

## 8. Secure Environment Loading (`sensitive.py`)
- Loads environment variables from `.env` if present, ensuring sensitive config is available before DB ops.

**Example:**
```python
from app.core.db_utils.sensitive import load_environment_files
load_environment_files()
```

---

## Best Practices
- Always compose decorators for robust, DRY, and secure DB operations.
- Use Prometheus metrics and logs for monitoring and troubleshooting.
- Prefer atomic, idempotent queries and handle all exceptions with custom error classes provided.
- Secure all sensitive data with encryption and environment validation.

For more details, see the code and docstrings in each file.