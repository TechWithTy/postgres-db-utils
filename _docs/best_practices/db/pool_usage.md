# Database Connection Pool Usage Guide

This module provides a robust, async-safe database connection pool with:

- Circuit breaker pattern for resilience
- Prometheus metrics for monitoring
- Exponential backoff and retry logic
- Async context management for FastAPI/Celery
- Strict production config validation

---

## Quickstart Example

```python
from app.core.db_utils.pool import ConnectionPool

pool = ConnectionPool()

# Get an async session (with circuit breaker, retries, metrics)
session = await pool.get_connection()

# Use with async context manager for transaction scope
async with pool.session_scope() as session:
    result = await session.execute(...)
    # ... your DB logic ...
```

---

## Key Features

- **Singleton Pattern:** `ConnectionPool()` always returns the same instance.
- **Configurable:** Reads settings from environment or `app.core.config.settings`.
- **Prometheus Metrics:** Exposes `/metrics` endpoint if `METRICS_ENABLED=true`.
- **Circuit Breaker:** Automatic fallback after repeated failures.
- **Exponential Backoff:** Retries connection attempts with increasing delay.
- **Async-First:** All connections and sessions are async (`AsyncSession`).
- **Event Listeners:** Tracks connection creation and reuse for metrics.

---

## Configuration

Set these in your environment or `settings`:

- `DATABASE_URL` (required, must be `postgresql+asyncpg://`)
- `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE`, `DB_POOL_TIMEOUT`
- `SQL_ECHO` (optional, SQL logging)
- `METRICS_ENABLED` (true/false), `METRICS_PORT` (default 9090)

---

## Production Best Practices

- Use only async DB drivers (`postgresql+asyncpg://`)
- Monitor `/metrics` for pool health and latency
- Tune pool size and overflow for your workload
- Handle `OperationalError`/`DisconnectionError` in your app logic
- Always close sessions (use `session_scope` or `await session.close()`)

---

## Troubleshooting

- **All connection attempts failed:** Check DB URL, credentials, network, and pool config.
- **Circuit breaker trips:** Investigate DB health and logs.
- **Metrics missing:** Ensure `METRICS_ENABLED` is set and port is open.
- **Warning: Invalid config values:** Defaults are used if settings are missing or invalid.

---

## Reference

- `ConnectionPool.get_connection() -> AsyncSession`
- `ConnectionPool.session_scope() -> async context manager`
- `ConnectionPool.close() -> Cleanup all connections`
- `ConnectionPool.metrics` (runtime stats)
- Prometheus metrics: `db_connection_attempts_total`, `db_connection_state`, `db_connection_latency_seconds`

---

*Guide updated 2025-05-13. For advanced usage, see inline code comments and Prometheus dashboards.*
