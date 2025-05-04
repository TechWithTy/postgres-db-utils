import asyncio
import logging
from typing import Any

from prometheus_client import Counter, Histogram

from app.core.pulsar.client import PulsarClient
from app.core.valkey.client import ValkeyClient

logger = logging.getLogger(__name__)

PULSAR_EVENTS_FORWARDED = Counter(
    "pulsar_events_forwarded", "Events forwarded from Valkey to Pulsar", ["topic"]
)
PULSAR_EVENTS_ENQUEUED = Counter(
    "pulsar_events_enqueued", "Events enqueued from Pulsar to Valkey", ["queue"]
)
PULSAR_HYBRID_PUBLISH = Counter(
    "pulsar_hybrid_publish", "Hybrid publish operations", ["topic", "channel"]
)
PULSAR_FORWARD_LATENCY = Histogram(
    "pulsar_forward_latency_seconds",
    "Latency for forwarding events from Valkey to Pulsar",
    ["topic"],
)


# --- Utility Functions: Direct Event Bridging ---
async def forward_valkey_events_to_pulsar(
    queue_name: str,
    topic: str,
    batch_size: int = 100,
) -> None:
    """
    Continuously poll Valkey queue and forward events to Pulsar topic.
    Use for high-throughput event ingestion or migration scenarios.
    """
    valkey_client = ValkeyClient()
    pulsar_client = PulsarClient()
    while True:
        try:
            events = await valkey_client.lrange(queue_name, 0, batch_size - 1)
            if not events:
                await asyncio.sleep(1)
                continue
            with PULSAR_FORWARD_LATENCY.labels(topic=topic).time():
                await pulsar_client.send_batch(topic=topic, messages=list(events))
            await valkey_client.ltrim(queue_name, batch_size, -1)
            PULSAR_EVENTS_FORWARDED.labels(topic=topic).inc(len(events))
        except Exception as e:
            logger.error(f"Error forwarding events to Pulsar: {e}")
            await asyncio.sleep(2)


async def pulsar_to_valkey_enqueue(
    topic: str,
    queue_name: str,
) -> None:
    """
    Consume from Pulsar topic and enqueue messages to Valkey queue for Celery/worker consumption.
    Use for replay, buffering, or hybrid fan-out.
    """
    pulsar_client = PulsarClient()
    valkey_client = ValkeyClient()
    subscription = f"{queue_name}-sub"

    async def callback(msg: dict):
        await valkey_client.rpush(queue_name, msg)
        PULSAR_EVENTS_ENQUEUED.labels(queue=queue_name).inc()

    try:
        await pulsar_client.consume_messages(
            topic=topic,
            subscription=subscription,
            callback=callback,
            retry_policy={"max_retries": 5, "delay": 1, "backoff_factor": 2},
        )
    except Exception as e:
        logger.error(f"Error consuming Pulsar topic '{topic}': {e}")
        await asyncio.sleep(2)


async def hybrid_publish(
    channel: str,
    topic: str,
    message: Any,
) -> None:
    """
    Publish a message to both Valkey pub/sub and Pulsar topic for dual-consumer scenarios.
    """
    valkey_client = ValkeyClient()
    pulsar_client = PulsarClient()
    try:
        await valkey_client.publish(channel, message)
        await pulsar_client.send_message(topic, message)
        PULSAR_HYBRID_PUBLISH.labels(topic=topic, channel=channel).inc()
    except Exception as e:
        logger.error(f"Error in hybrid_publish: {e}")
