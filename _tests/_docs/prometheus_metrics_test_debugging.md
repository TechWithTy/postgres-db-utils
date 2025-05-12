# Debugging and Passing Prometheus Metrics & DB Tests in Modular Python Codebases

**Last Updated:** 2025-05-12 14:18:00

---

## Context: How to Debug DB Tests in This Repo

### Test Isolation, Settings Mocking, and Environment Handling

- **Settings & Environment Mocking:**
  - All DB and metrics settings are injected via environment variables or a `settings` object (see `app/core/config.py`).
  - Tests use fixtures (e.g., `mock_env`, `patch_settings`) to override env vars and settings for each test or test session.
  - Example: `DATABASE_URL`, `METRICS_ENABLED`, and `SECRET_KEY` are always set in the test environment to prevent accidental use of production values.
  - Use `monkeypatch` or `pytest` fixtures to patch settings and env vars before module import or reload.

- **Prometheus Metrics & Registry:**
  - Metrics are never defined at the module level; use a factory (e.g., `get_metrics()`) to create them on demand.
  - The Prometheus registry is patched at the start of the test session (see `conftest.py`) so all metrics use a test-local registry.
  - The patch ensures `registry` is only injected if not already present to avoid double-injection errors.

- **Reloads & Process Isolation:**
  - Any test that reloads modules or dynamically re-imports metric definitions should use `pytest.mark.forked` to run in a separate process.
  - This prevents registry and metric state from leaking between tests.

- **Debugging Best Practices:**
  - If you see `Duplicated timeseries` errors, check for:
    - Metrics defined at module level
    - Registry not being patched or cleared
    - Tests not running in a forked process when needed
  - Always document your debugging steps and timestamp them in this file for future maintainers.

---

## Overview

This document describes the strategies, timestamped learnings, and best practices used to resolve persistent `Duplicated timeseries in CollectorRegistry` errors and achieve robust, repeatable Prometheus metrics testing in this codebase.

## Timeline & Key Steps

- **2025-05-12 14:10:** Identified that metric duplication errors were caused by module-level Prometheus metric definitions and registry state leaking between test runs and reloads.
- **2025-05-12 14:12:** Refactored all metric definitions (`Counter`, `Gauge`, `Histogram`) into a `get_metrics()` function to avoid import-time registration.
- **2025-05-12 14:13:** Patched `prometheus_client` in `conftest.py` to inject a fresh `CollectorRegistry` for every test session and to avoid double-injecting the `registry` kwarg.
- **2025-05-12 14:14:** Added `pytest.mark.forked` to tests that reload metric-defining modules, ensuring process-level isolation for problematic tests.
- **2025-05-12 14:15:** Updated all metric usages to fetch metrics via `get_metrics()` inside methods, ensuring no global metric state.
- **2025-05-12 14:16:** All tests pass; registry and metric duplication errors fully resolved.

## Best Practices for Debugging Prometheus Metrics in Python Tests

- **Never define metrics at module level** if you plan to reload modules or run tests in the same process. Use a factory function (e.g., `get_metrics()`).
- **Patch the Prometheus registry at the start of your test session** using a `pytest_configure` hook. Only inject `registry` if not already present in kwargs.
- **Isolate problematic tests with `pytest.mark.forked`** (requires `pytest-xdist`). This fully resets interpreter state and avoids registry leaks.
- **Update all metric usages** to call your metric factory function within each method or test, not at the class or module level.
- **If you see `Duplicated timeseries` errors:**
  - Check for any lingering references to old metric objects.
  - Ensure the registry is not being reused across test sessions or module reloads.
  - Use `registry.unregister()` if you must, but prefer process isolation or functional metric creation.
- **Document your debugging steps and timestamp them** so future maintainers know what was tried and why.

## Example: Safe Metric Usage Pattern

```python
# In pool.py
from prometheus_client import Counter, Gauge, Histogram

def get_metrics():
    DB_CONNECTION_ATTEMPTS = Counter(...)
    DB_CONNECTION_STATE = Gauge(...)
    DB_CONNECTION_LATENCY = Histogram(...)
    return DB_CONNECTION_ATTEMPTS, DB_CONNECTION_STATE, DB_CONNECTION_LATENCY

# In your method
DB_CONNECTION_ATTEMPTS, DB_CONNECTION_STATE, DB_CONNECTION_LATENCY = get_metrics()
DB_CONNECTION_ATTEMPTS.labels(status="attempt").inc()
```

## Key Lessons Learned

- Test isolation is critical for metrics libraries that use global state.
- Dynamic module reloads and patching require careful control of import-time side effects.
- Always automate registry patching and metric instantiation for robust, CI-friendly tests.

---

*For more patterns and troubleshooting, see the `_docs` folder or contact the maintainers.*
