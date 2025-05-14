# Database Decorators Usage Guide

This module provides reusable decorators for robust, DRY, and secure database operations:

- Retry logic with exponential backoff
- Automatic connection management
- Query optimization
- Pool metrics tracking
- Secure environment loading
- Transparent encryption/decryption

---

## Quick Reference

### 1. Retry Decorator

```python
from app.core.db_utils.decorators import retry_decorator

@retry_decorator(max_retries=5)
async def my_db_op(...):
    ...
```
- Retries on `RetryableError` and `ConnectionError` by default.
- Exponential backoff (max 10s).
- Logs all attempts and failures.

---

### 2. Managed DB Connection

```python
from app.core.db_utils.decorators import with_engine_connection

@with_engine_connection
async def do_with_connection(conn):
    # conn is an AsyncConnection from SQLAlchemy
    ...
```
- Injects an async DB connection.
- Handles engine creation and cleanup.

---

### 3. Query Optimization

```python
from app.core.db_utils.decorators import with_query_optimization

@with_query_optimization
async def fetch_optimized(...):
    # QueryOptimizer is applied automatically
    ...
```
- Integrates with `db_optimizations.py` for best-practice query handling.

---

### 4. Pool Metrics Tracking

```python
from app.core.db_utils.decorators import with_pool_metrics

@with_pool_metrics
async def monitored_db_task(...):
    ...
```
- Tracks connection pool stats via Prometheus.

---

### 5. Secure Environment Loading

```python
from app.core.db_utils.decorators import with_secure_environment

@with_secure_environment
async def sensitive_task(...):
    ...
```
- Ensures environment files are loaded securely before running.

---

### 6. Encrypted Parameters

```python
from app.core.db_utils.decorators import with_encrypted_parameters

@with_encrypted_parameters
async def handle_sensitive(data: str):
    # data is transparently decrypted/encrypted
    ...
```
- Uses `DataEncryptor` for parameter encryption/decryption.

---

## Best Practices

- Stack decorators as needed for DRY, robust DB logic.
- Always use retry for network/DB ops in production.
- Use query optimization to avoid N+1 and improve performance.
- Monitor Prometheus metrics for pool health and retry rates.
- Never log decrypted sensitive data.
- For custom retryable errors, subclass `RetryableError`.

---

## Troubleshooting

- **Retries exhausted:** Check DB/network health and logs.
- **Decorator order:** Place retry outermost for most robust error handling.
- **Metrics not updating:** Ensure Prometheus is running and pool is properly configured.
- **Encryption errors:** Check key config and usage of `with_encrypted_parameters`.

---

## Reference

- `retry_decorator(max_retries=3, exceptions=(...))`
- `with_engine_connection`
- `with_query_optimization`
- `with_pool_metrics`
- `with_secure_environment`
- `with_encrypted_parameters`

---

*Guide updated 2025-05-13. For advanced usage, see inline code comments.*
