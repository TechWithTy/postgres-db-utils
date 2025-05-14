# Prometheus API Metrics: Best Practices

This guide covers how to track API calls, latency, and status codes in FastAPI or worker services using Prometheus. It includes how to define metrics in config classes, register them, and use them in endpoints for full observability.

---

## 1. Defining Prometheus Metrics in Config Classes

Define metrics as class attributes for DRY, discoverable usage:

```python
class GHLConfig(IOTaskConfig):
    """Base configuration class for GHL services using IOTaskConfig base model"""
    HISTOGRAM: ClassVar[tuple[str, str, list[str]]] = (
        "ghl_latency_seconds",
        "GHL API call processing time",
        ["endpoint"],
    )
    COUNTER: ClassVar[tuple[str, str, list[str]]] = (
        "ghl_calls_total",
        "Total GHL API calls",
        ["endpoint", "status"],
    )
    # ...other config attributes
```

---

## 2. Registering Metrics

In your app startup or metrics module:

```python
from prometheus_client import Histogram, Counter
from app.api.based_routes.ghl.config import GHLConfig

ghl_latency = Histogram(*GHLConfig.HISTOGRAM)
ghl_calls = Counter(*GHLConfig.COUNTER)
```

---

## 3. Using Metrics in Endpoints or Workers

Wrap your FastAPI route or worker logic:

```python
@app.post("/ghl-action")
async def ghl_action(...):
    with ghl_latency.labels(endpoint="/ghl-action").time():
        try:
            # ...call logic
            ghl_calls.labels(endpoint="/ghl-action", status="success").inc()
            return {"ok": True}
        except Exception:
            ghl_calls.labels(endpoint="/ghl-action", status="error").inc()
            raise
```
- Always label metrics with endpoint and status for observability.
- Use `.time()` context manager for latency.
- Increment counters on both success and error.

---

## Example: Using prometheus_client Directly

```python
from prometheus_client import Histogram, Counter

# Define metrics at module level
REQUEST_LATENCY = Histogram(
    'db_query_latency_seconds',
    'Latency of DB queries',
    ['endpoint', 'status']
)
REQUEST_COUNT = Counter(
    'db_query_total',
    'Total DB queries',
    ['endpoint', 'status']
)

def query_db():
    endpoint = '/db/query'
    status = 'success'
    with REQUEST_LATENCY.labels(endpoint, status).time():
        try:
            # ... your DB logic ...
            result = run_query()
            REQUEST_COUNT.labels(endpoint, status).inc()
            return result
        except Exception:
            status = 'error'
            REQUEST_COUNT.labels(endpoint, status).inc()
            raise
```
*This pattern is production-grade: define metrics at module level, label every call, and use `.time()` for latency. See your CPU/DB endpoint patterns for integration tips.*

---

## 4. Best Practices
- Use config classes to centralize metric definitions and avoid duplication.
- Track both latency and call count for every endpoint.
- Label metrics with endpoint and status for filtering in Grafana.
- Expose `/metrics` endpoint for Prometheus scraping.
- Use Prometheus Alertmanager to trigger on high error rates or latency spikes.

---

*See also: [Prometheus Python client docs](https://github.com/prometheus/client_python) and your `config.py` for metric constants.*

*Last updated: 2025-05-13*
