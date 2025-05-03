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