# When to Use Valkey + Celery vs. Valkey + Celery + Pulsar

## Overview

This document provides guidance on selecting the right distributed task processing stack for your use case:
- **Valkey + Celery** (classic, reliable, Python-centric)
- **Valkey + Celery + Pulsar** (scalable, streaming, multi-language, advanced)

---

## 1. Valkey + Celery

**Use when:**
- Your workflows are primarily Python-based and synchronous or batch-oriented.
- You need robust distributed task queues with retry, scheduling, and result backend support.
- Real-time streaming or cross-language consumption is NOT required.
- You want simple, well-supported patterns for caching, rate limiting, and idempotency.
- You are migrating from Redis and want a drop-in, cloud-native alternative.

**Typical scenarios:**
- Background jobs (emails, report generation, batch data sync)
- Database maintenance and ETL tasks
- API-triggered workflows where latency is not ultra-critical
- Tasks requiring strong result tracking and error handling

**Strengths:**
- Mature ecosystem, easy to monitor and debug
- Built-in retry, scheduling, and result storage
- Tight integration with Python async/await and Pydantic validation
- Supports Valkey for cache, pub/sub, and queue

---

## 2. Valkey + Celery + Pulsar

**Use when:**
- You require high-throughput, real-time, or streaming data pipelines.
- Workflows involve multiple languages (Python, Java, Go, etc.) or systems.
- You need features like dead-letter queues (DLQ), message replay, and advanced delivery guarantees (exactly-once).
- You want to decouple producers and consumers for microservices or event-driven architectures.
- Geo-replication, horizontal scaling, or persistent queues are critical.

**Typical scenarios:**
- Real-time analytics, ingestion pipelines, and event sourcing
- Cross-service communication in microservice architectures
- Multi-language consumers (e.g., ML in Python, analytics in Java)
- Large-scale, distributed systems with strict SLAs

**Strengths:**
- High scalability and throughput (>10K msg/sec)
- Built-in DLQ, message retention, replay, and monitoring
- Decouples task production and consumption
- Supports both streaming and queue semantics

---

## 3. Decision Table

| Use Case                                 | Valkey + Celery | Valkey + Celery + Pulsar |
|-------------------------------------------|-----------------|--------------------------|
| Python-only, batch jobs                   | | |
| Real-time streaming/events                | | |
| Multi-language consumers                  | | |
| Simple background tasks                   | | |
| High throughput, geo-replication needed   | | |
| DLQ, replay, advanced delivery guarantees | | |
| Pub/Sub or polling only                   | | |
| Hybrid (batch + streaming)                | | |

---

## 4. Hybrid Patterns

In some cases, you may combine both stacks:
- Use Celery for orchestration and result tracking, Pulsar for streaming/event ingestion, and Valkey for caching/idempotency.
- Example: Ingest events via Pulsar, process in Python with Celery, cache results in Valkey.

---

## 5. References

- See [core.md](./core.md), [pulsar.md](./pulsar.md), [valkey-pulsar.md](./valkey-pulsar.md), and [valkey.md](./valkey.md) for detailed setup and best practices.
