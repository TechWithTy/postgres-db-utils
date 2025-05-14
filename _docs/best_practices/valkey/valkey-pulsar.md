# Valkey + Pulsar + Celery: Hybrid Worker Patterns

This guide explains how and when to combine Valkey, Pulsar, and Celery for advanced distributed task processing, streaming, and event-driven microservices. It provides best-practice patterns and real-world examples for hybrid architectures.

---

## 1. Overview

Hybrid patterns leverage:
- **Valkey** for caching, idempotency, pub/sub, and queueing
- **Pulsar** for high-throughput streaming, DLQ, replay, and multi-language support
- **Celery** for Python task orchestration, retries, scheduling, and result tracking

---

## 2. When to Use Hybrid Patterns

**Use hybrid Valkey + Pulsar + Celery when:**
- You need to ingest, buffer, and process high-velocity events with both batch and real-time requirements
- Some consumers are Python (Celery), others are non-Python or streaming (Pulsar)
- You require advanced DLQ, replay, idempotency, and monitoring
- You want to decouple event ingestion (Pulsar) from processing (Celery), with Valkey as a cache or deduplication layer

**Typical scenarios:**
- IoT, telemetry, or analytics pipelines with mixed batch and streaming
- Microservices where some services consume via Pulsar, others via Celery
- Workflows needing both strong result tracking (Celery) and real-time streaming (Pulsar)

---

## 3. Example Architecture

1. **Event Ingestion:**
   - Producer publishes events to Pulsar topic
   - Pulsar consumer writes events to Valkey (for caching, deduplication, or queueing)
2. **Processing:**
   - Celery worker polls Valkey queue, processes events, and publishes results
   - Optionally, Celery can send processed events back to Pulsar for further streaming
3. **Deduplication:**
   - Use Valkey TTL keys to prevent duplicate event processing
4. **DLQ & Replay:**
   - Pulsar handles DLQ and message replay for failed events

---

## 4. Best Practices

- Use strict Pydantic models for all task payloads and configs
- Prefer async/await for all I/O and network-bound tasks
- Apply per-task rate limiting and circuit breaking
- Use Valkey as a cache for idempotency (store event IDs/hashes with TTL)
- Use Pulsar for delivery guarantees, DLQ, and replay
- Use Celery for Python task orchestration, retries, and scheduling
- Monitor all components with Prometheus and structured logging
- Configure all timeouts, retries, and limits via environment/config

---

## 5. Example: Hybrid Worker Registration

```python
from app.core.db_utils.workers.valkey_pulsar import run_io_task_with_best_practices_valkey_pulsar, PulsarIOTaskConfig

@run_io_task_with_best_practices_valkey_pulsar(
    config=PulsarIOTaskConfig(
        topic="persistent://prod/ingest/hybrid",
        dlq_topic="persistent://prod/ingest/hybrid-dlq",
        channel="hybrid_events",
        cache_ttl=300,
        rate_limit=500,
        rate_window=60,
        max_retries=3,
        backoff=2,
        task_timeout=30,
        batch_size=100
    )
)
async def process_hybrid_event(event: dict) -> None:
    # Deduplicate via Valkey
    # Process event
    # Optionally publish to Pulsar and/or Celery
    pass
```

---

## 6. Monitoring & Troubleshooting

- Monitor queue depth in Valkey and Pulsar topics
- Track DLQ and replay events
- Use Prometheus metrics for throughput, error rates, and latency
- Log all failures with structured, sanitized logs

---

## 7. References

- [Valkey Worker Guide](./valkey.md)
- [Pulsar Task Best Practices](./pulsar.md)
- [Celery Best Practices](https://docs.celeryq.dev/en/stable/userguide/tasks.html)

---

## 8. TODOs
- Add more advanced circuit breaker and fallback logic
- Provide multi-language consumer examples
- Expand on hybrid orchestration patterns