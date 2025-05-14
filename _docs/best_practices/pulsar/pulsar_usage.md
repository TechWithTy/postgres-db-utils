# Pulsar Usage Guide

This document explains how to use Pulsar in this project using the actual core implementation.

---

## 1. Import Core Pulsar Components

```python
from app.core.pulsar.client import PulsarClient
from app.core.pulsar.decorators import pulsar_task, pulsar_consumer
from app.core.pulsar.metrics import PULSAR_MESSAGE_LATENCY, pulsar_errors, pulsar_messages_sent
from app.core.pulsar.config import PulsarConfig
from app.core.pulsar.health_check import check_pulsar_health
```

---

## 2. Define a Pulsar Task (Producer) with Decorator

```python
@pulsar_task(
    topic="persistent://prod/ingest/events",
    dlq_topic="persistent://prod/ingest/events-dlq",
    max_retries=3,
    retry_delay=2.0
)
async def process_event(event: dict) -> dict:
    # Your business logic here
    return {"status": "processed", **event}
```

---

## 3. Sending a Message (Producer Usage)

```python
client = PulsarClient()
event = {"type": "user_signup", "user_id": 123}
await process_event(event)  # The decorator will handle sending to Pulsar
```

---

## 4. Consuming Messages (Consumer Example)

```python
@pulsar_consumer(
    topic="persistent://prod/ingest/events",
    subscription="my-consumer-group",
    max_parallelism=10
)
async def handle_event(message: dict):
    # Process the message
    ...
```

---

## 5. Metrics and Monitoring

- All tasks automatically emit Prometheus metrics:
  - `pulsar_messages_sent.labels(topic=...).inc()`
  - `PULSAR_MESSAGE_LATENCY.labels(topic=...).observe(duration)`
  - `pulsar_errors.labels(type=...).inc()`
- See `app/core/pulsar/metrics.py` for details.

---

## 6. Health Checks & Config

```python
await check_pulsar_health()
print(PulsarConfig.SECURITY)
```

---

## 7. Best Practices

- Use the decorators for all Pulsar task/consumer logic—this ensures retry, DLQ, metrics, and RBAC are enforced.
- Always validate topic/role permissions (handled by the decorator).
- Monitor Prometheus metrics for errors, latency, and throughput.
- Use async/await for all Pulsar I/O.
- Reference the actual modules above for advanced patterns (batch, filtering, custom retry, etc).

---

*See also: [client.py](../../../../pulsar/client.py), [decorators.py](../../../../pulsar/decorators.py), [metrics.py](../../../../pulsar/metrics.py), [config.py](../../../../pulsar/config.py), [health_check.py](../../../../pulsar/health_check.py)*
