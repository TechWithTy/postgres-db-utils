# Pulsar Best Practices for This Project

This section documents production-grade patterns for using Apache Pulsar with Valkey, Celery, and FastAPI in this codebase. It reflects your actual structure and code idioms.

---

## 1. Valkey <-> Pulsar Bridging
- Use async workers to forward events from Valkey queues to Pulsar topics (`valkey_to_pulsar_forwarder`).
- Use async consumers to enqueue Pulsar messages into Valkey for Celery/worker consumption (`pulsar_to_valkey_enqueue`).
- Support replay, buffering, and hybrid fan-out for high-throughput, reliable event delivery.

## 2. Prometheus Metrics
- Track Pulsar forwarding latency and event counts with Prometheus metrics (e.g., `PULSAR_FORWARD_LATENCY`, `PULSAR_EVENTS_FORWARDED`).
- Label metrics with topic and status for observability and alerting.

## 3. Error Handling & Retries
- Use robust try/except blocks around all I/O.
- Log errors with context (topic, queue, exception).
- Use async sleep between retries to avoid hot loops.
- Consider circuit breaker or retry decorators for critical forwarding/consuming logic.

## 4. Async Patterns
- All queue and Pulsar operations are fully async for maximum throughput and non-blocking behavior.
- Use batch operations (e.g., `send_batch`) for efficiency.

## 5. Role/Permission Validation
- Use decorators (e.g., `permission_role_guard`) to enforce RBAC on worker tasks and endpoints.
- Log and raise HTTP 403 on permission failures, with sanitized logs.

## 6. Circuit Breaker & Retry Patterns
- Use retry decorators (e.g., with `tenacity` or custom) for transient Pulsar/Valkey failures.
- Use circuit breaker patterns for repeated failures to avoid cascading outages.
- Log all retry/circuit events for monitoring.

## 7. Failover & Monitoring
- Monitor queue depths, error rates, and latency via Prometheus/Grafana.
- Alert on high error rates, slow forwards, or queue build-up.
- Periodically test failover and replay scenarios.

---

# Pulsar Task Best Practices

## Core Concepts
- **Pub/Sub Model**: Decoupled message producers/consumers  
- **DLQ Handling**: Automatic dead-letter queue routing  
- **Topic Patterns**:  
  ```python
  topic="persistent://tenant/namespace/topic-name"  
  dlq_topic=f"{topic}-dlq"   
  ```

## Configuration Examples  

### Basic I/O Task  
```python
@run_io_task_with_best_practices_pulsar(
    config=PulsarIOTaskConfig(
        topic="persistent://prod/ingest/raw-data",
        dlq_topic="persistent://prod/ingest/raw-data-dlq", 
        rate_limit=500,  # messages
        rate_window=60,  # seconds
        max_retries=3,
        backoff=2,  # exponential backoff base
        task_timeout=30  # seconds
    )
)
async def ingest_data(payload: dict) -> dict:
    return await validate_and_transform(payload)
```

### DB Task with Permissions  
```python 
@run_db_task_with_best_practices_pulsar(
    config=PulsarDBTaskConfig(
        topic="persistent://prod/db/writes",
        permission_roles=["db_writer"],
        credit_type="db_credits", 
        credit_amount=2
    )
)
async def write_records(records: list[dict]) -> int:
    return await bulk_insert(records)
```

## Pulsar Cluster Setup  

### Recommended Production Setup  
```yaml
# docker-compose.yaml
pulsar:
  image: apachepulsar/pulsar:3.1.0
  ports:
    - "6650:6650"  # Broker
    - "8080:8080"  # Dashboard
  volumes:
    - pulsar-data:/pulsar/data
  command: >
    bin/pulsar standalone
    -nss  
    -c broker.conf=autoTopicCreationEnabled=true
```

### Key Configuration Parameters  
| Parameter | Recommended Value | Description |  
|-----------|-------------------|-------------|  
| `brokerDeduplicationEnabled` | true | Prevent duplicate messages |  
| `backlogQuotaDefaultLimitGB` | 50 | Max backlog per topic |  
| `managedLedgerDefaultEnsembleSize` | 3 | Bookie replicas |  

## Celery vs Pulsar Comparison  

### When to Use Pulsar  
- **High throughput** (>10K msg/sec)  
- **Geo-replication** needed  
- **Persistent queues** required  
- **Multi-language** consumers  

### When to Use Celery  
- **Simple workflows**  
- **Python-only** ecosystem  
- **Synchronous** task patterns  

### Feature Matrix  
| Feature | Pulsar | Celery |  
|---------|--------|--------|  
| Delivery Guarantees | Exactly-once | At-least-once |  
| Horizontal Scaling | Built-in | Requires broker |  
| Message Retention | Configurable | Until consumed |  
| Priority Queues | Yes | Yes |  
| DLQ Handling | Automatic | Manual |  

## Monitoring & Alerting
```python
# Prometheus Metrics
from prometheus_client import start_http_server
start_http_server(9090)  # Exposes /metrics endpoint
```

## Performance Optimization
- **Batching**: Enable message chunking  
- **Compression**: LZ4 or Zstandard  
- **Ack Timeout**: Set based on SLA (default: 30s)  
```python
pulsar_task(..., ack_timeout=60)  # 60 seconds
```

## Troubleshooting Scenarios

### 1. High Consumer Lag
**Symptoms**:
- Growing message backlog
- Increasing publish latency

**Resolution**:
```python
# Scale consumers horizontally
@run_io_task_with_best_practices_pulsar(
    config=PulsarIOTaskConfig(
        consumer_name=f"worker-{os.getpid()}",  # Unique consumer ID
        receiver_queue_size=1000  # Increase prefetch
    )
)
```

### 2. DLQ Flooding
**Symptoms**:
- DLQ topic growing rapidly
- Repeated message failures

**Debugging**:
```bash
# Inspect DLQ messages
pulsar-client consume "persistent://tenant/ns/topic-dlq" -s sub-name -n 10
```

## Alerting Rules

### Prometheus Alert Examples
```yaml
# High Backlog Alert
- alert: PulsarBacklogCritical
  expr: pulsar_subscription_back_log > 10000
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "High backlog on {{ $labels.topic }}"

# Consumer Failure Alert  
- alert: PulsarConsumerFailures
  expr: rate(pulsar_consumer_failures[1m]) > 5
  labels:
    severity: warning
  annotations:
    description: "{{ $value }} consumer failures/min on {{ $labels.topic }}"
```

## Recovery Procedures

### Message Replay from DLQ
```python
from app.core.pulsar import replay_dlq_messages

async def reprocess_failures():
    await replay_dlq_messages(
        original_topic="persistent://prod/ingest/orders",
        dlq_topic="persistent://prod/ingest/orders-dlq",
        processor=validate_and_retry
    )
```

## Grafana Dashboard Examples
```json
{
  "panels": [{
    "title": "Pulsar Throughput",
    "type": "graph",
    "targets": [{
      "expr": "rate(pulsar_producer_throughput[1m])",
      "legendFormat": "{{topic}}"
    }]
  }]
}
```

## Chaos Engineering Tests
```python
# Test scenario: Broker failure
def test_broker_failure():
    stop_broker()
    publish_messages()  # Should buffer
    start_broker()
    verify_message_delivery()
```

## Zero-Downtime Upgrades
```bash
# Rolling restart procedure
pulsar-admin brokers restart --broker broker1:8080
```

## Client SDK Configuration
```python
# Python client best practices
client = pulsar.Client(
    'pulsar://localhost:6650',
    operation_timeout_seconds=30,
    connection_timeout_ms=5000
)

```

## Pulsar Integration Patterns for Valkey + Celery

This guide explains how and when to integrate Apache Pulsar with your existing Valkey + Celery stack.

### Why Integrate Pulsar?
- **High-throughput streaming:** For workloads that exceed Valkey/Redis pub/sub or queueing limits.
- **Durable event retention and replay:** Needed for analytics, audit, or regulatory workloads.
- **Multi-tenant isolation:** Clean per-client/topic separation.
- **Complex event topologies:** Fan-out, long-lived subscriptions, or cursor-based consumption.

### Integration Strategies

#### 1. Hybrid Event Pipeline
Bridge Valkey queues with Pulsar topics using [`valkey-pulsar.py`](../valkey-pulsar.py):
- Forward events from Valkey queue to Pulsar for ingestion or migration.
- Subscribe to Pulsar and enqueue to Valkey for replay or hybrid worker consumption.
- Use hybrid publish to send to both for dual-consumer scenarios.

#### 2. Migration Path
- Start with Celery + Valkey for most workloads.
- Pilot Pulsar for a high-volume, streaming-critical use case.
- Gradually expand Pulsar only if it provides clear benefits (retention, replay, multi-subscription).

#### 3. Operational Considerations
- Pulsar adds operational complexity (BookKeeper, ZooKeeper, monitoring).
- Use Prometheus/OpenTelemetry for monitoring queue lag, throughput, and errors.
- Only add Pulsar if you hit Valkey/Redis scaling or feature limits.

### Example: Forwarding Events
```python
from app.core.db_utils.workers.valkey-pulsar import forward_valkey_events_to_pulsar

await forward_valkey_events_to_pulsar(valkey_client, pulsar_producer, 'my_queue', 'my_topic')
```

### Example: Hybrid Publish
```python
from app.core.db_utils.workers.valkey-pulsar import hybrid_publish

await hybrid_publish(valkey_client, pulsar_producer, 'my_channel', 'my_topic', my_message)
```

---

For more, see [`valkey.md`](./valkey.md) and Pulsar's official docs.
