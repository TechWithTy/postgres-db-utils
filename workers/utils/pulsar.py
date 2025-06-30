import asyncio
import json
import logging
import time
import uuid
from typing import Any, Dict, Optional, List, Union
from fastapi import BackgroundTasks

from prometheus_client import Counter, Histogram

from app.core.pulsar.client import PulsarClient
from app.core.valkey_core.client import ValkeyClient
from app.core.config import settings
from app.core.prometheus.metrics import get_event_count, get_event_latency

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

# Global cache for Pulsar client to avoid repeated initialization
_pulsar_client = None


def get_pulsar_client():
    """Get or initialize the Pulsar client."""
    global _pulsar_client
    if _pulsar_client is None:
        _pulsar_client = PulsarClient()
    return _pulsar_client


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


# --- Enhanced Event Publishing Functions ---

async def publish_event(topic: str, data: Dict[str, Any], schema: Optional[str] = None) -> bool:
    """
    Publish an event to a Pulsar topic synchronously.
    This function will block until the message is acknowledged by Pulsar.
    
    Args:
        topic: The Pulsar topic to publish to
        data: The data to publish (will be serialized to JSON)
        schema: Optional schema name for the message
        
    Returns:
        bool: True if the message was successfully published
    """
    start_time = time.time()
    client = get_pulsar_client()
    
    try:
        # Add metadata to the event
        enriched_data = {
            **data,
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
        }
        
        if schema:
            enriched_data["schema"] = schema
            
        # Convert to JSON if it's not already a string
        message = enriched_data if isinstance(enriched_data, str) else json.dumps(enriched_data)
        
        # Send the message
        await client.send_message(topic, message)
        
        # Record metrics
        duration = time.time() - start_time
        get_event_count().labels(topic=topic, result="success").inc()
        get_event_latency().labels(topic=topic).observe(duration)
        
        logger.debug(f"Published event to {topic}")
        return True
    except Exception as e:
        # Record error metrics
        duration = time.time() - start_time
        get_event_count().labels(topic=topic, result="error").inc()
        get_event_latency().labels(topic=topic).observe(duration)
        
        logger.error(f"Error publishing event to {topic}: {e}")
        return False


def _background_publish_task(topic: str, data: Dict[str, Any], schema: Optional[str] = None):
    """Non-async wrapper for background tasks to publish events."""
    import asyncio
    import time
    from app.core.prometheus.metrics import get_event_count, get_event_latency
    
    start_time = time.time()
    max_retries = 3
    retry_count = 0
    
    try:
        # Create a new event loop for this background task
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Add retry logic for better reliability
        last_error = None
        while retry_count < max_retries:
            try:
                # Run the coroutine until complete
                result = loop.run_until_complete(publish_event(topic, data, schema))
                
                # Record success metrics
                duration = time.time() - start_time
                get_event_count().labels(topic=topic, result="success_background").inc()
                get_event_latency().labels(topic=topic).observe(duration)
                
                logger.debug(f"Successfully published event to {topic} in background task")
                return result
            except Exception as e:
                retry_count += 1
                last_error = e
                logger.warning(f"Background publish attempt {retry_count}/{max_retries} to {topic} failed: {str(e)}")
                
                # Exponential backoff
                if retry_count < max_retries:
                    time.sleep(0.5 * (2 ** retry_count))  # 1s, 2s, 4s
        
        # If we got here, all retries failed
        if last_error:
            logger.error(f"All background publish attempts to {topic} failed: {str(last_error)}")
            
        # Record failure metrics
        duration = time.time() - start_time
        get_event_count().labels(topic=topic, result="error_background").inc()
        get_event_latency().labels(topic=topic).observe(duration)
        
        return False
    except Exception as e:
        # Record critical failure metrics
        duration = time.time() - start_time
        get_event_count().labels(topic=topic, result="critical_error").inc()
        get_event_latency().labels(topic=topic).observe(duration)
        
        logger.error(f"Critical error in background event publishing to {topic}: {e}")
        return False
    finally:
        # Always close the event loop
        try:
            loop.close()
        except Exception as close_error:
            logger.debug(f"Error closing event loop: {str(close_error)}")


async def hybrid_publish(
    topic: str,
    data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    schema: Optional[str] = None
) -> bool:
    """
    Enhanced hybrid approach to publishing events:
    1. Try to publish quickly without waiting for acknowledgment
    2. If that fails, queue the event for publishing in a background task
    
    This provides the best balance of reliability and performance.
    
    Args:
        topic: The Pulsar topic to publish to
        data: The data to publish
        background_tasks: FastAPI BackgroundTasks object to use for background publishing
        schema: Optional schema name for the message
        
    Returns:
        bool: True if the publish operation was initiated successfully
    """
    try:
        # Try a quick non-blocking publish first
        try:
            client = get_pulsar_client()
            if client is None:
                # If client initialization fails, go straight to background task
                logger.warning("Failed to get Pulsar client, falling back to background task")
                raise Exception("Failed to get Pulsar client")
                
            # Add metadata to the event
            enriched_data = {
                **data,
                "event_id": str(uuid.uuid4()),
                "timestamp": time.time(),
            }
            
            if schema:
                enriched_data["schema"] = schema
                
            # Convert to JSON if it's not already a string
            message = enriched_data if isinstance(enriched_data, str) else json.dumps(enriched_data)
            
            # Try to send with a very short timeout
            try:
                # Use a very short timeout for the quick attempt
                # This will either succeed quickly or fail quickly
                await asyncio.wait_for(client.send_message(topic, message), timeout=0.05)
                
                # If we get here, the message was sent successfully
                get_event_count().labels(topic=topic, result="success").inc()
                logger.debug(f"Quick published event to {topic}")
                return True
            except (asyncio.TimeoutError, Exception) as e:
                # The quick publish timed out or failed, fall back to background task
                logger.debug(f"Quick publish failed for {topic} with error {str(e)}, using background task")
                pass
                
            # If we get here, the quick publish failed or timed out
            # Queue the event for reliable delivery in a background task
            background_tasks.add_task(_background_publish_task, topic, enriched_data, schema)
            get_event_count().labels(topic=topic, result="queued").inc()
            logger.debug(f"Queued event for background publishing to {topic}")
            return True
        except Exception as inner_e:
            # Handle any unexpected error in the quick publish attempt
            logger.warning(f"Error in quick publish to {topic}: {str(inner_e)}")
            
            # Still try the background task as a fallback
            enriched_data = {
                **data,
                "event_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "error_recovery": True,  # Flag to indicate this was a recovery attempt
            }
            if schema:
                enriched_data["schema"] = schema
                
            background_tasks.add_task(_background_publish_task, topic, enriched_data, schema)
            get_event_count().labels(topic=topic, result="queued_fallback").inc()
            logger.debug(f"Queued event for fallback background publishing to {topic}")
            return True
    except Exception as e:
        # Something went wrong with the entire process
        get_event_count().labels(topic=topic, result="error").inc()
        logger.error(f"Error in hybrid_publish to {topic}: {e}")
        return False
