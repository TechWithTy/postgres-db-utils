# Tracing Database Worker Tasks with OpenTelemetry

This guide explains how to track traces and monitor performance in your worker utilities using OpenTelemetry-powered decorators from `app.core.telemetry.decorators`.

---

## Overview
- **Decorators:**
  - `@trace_function`: Adds OpenTelemetry traces to any function or task.
  - `@measure_performance`: Records performance metrics (duration, status).
  - `@track_errors`: Automatically records exceptions and error traces.
- **Stack:** OpenTelemetry, Prometheus, FastAPI, Celery, and custom DB workers.

---

## Usage Example

```python
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)

@trace_function
@measure_performance
@track_errors
async def run_db_worker_task(config: DBTaskConfig):
    # Your DB or I/O logic here
    ...
```

- **Order:** Place `@trace_function` outermost for full trace context. `@measure_performance` and `@track_errors` can be stacked in any order.
- **Async Support:** All decorators support async and sync functions.

---

## How It Works
- **@trace_function:** Automatically creates a trace span for the function, including input parameters and context. If called within an existing trace (e.g., FastAPI request), the span is nested for end-to-end visibility.
- **@measure_performance:** Records execution time and status as Prometheus metrics, tagged with function name and custom labels.
- **@track_errors:** Captures exceptions, logs them, and attaches error details to the trace.

---

## Best Practices
- Use `@trace_function` on all entry points for worker tasks, API endpoints, and background jobs.
- Combine with `@measure_performance` for real-time latency and status monitoring.
- Use `@track_errors` to ensure all exceptions are visible in traces and logs.
- Configure your OpenTelemetry exporter (OTLP, Jaeger, etc.) in your settings for full trace visibility.

---

## Example: FastAPI Endpoint

```python
from fastapi import APIRouter
from app.core.telemetry.decorators import trace_function

router = APIRouter()

@router.post("/run-task")
@trace_function
async def run_task_endpoint(...):
    ...
```

---

## Security & Compliance
- Do not log sensitive data in trace attributes.
- Use sampling and retention policies appropriate for your environment.

---

*Last updated: 2025-05-13*
