# backend/app/core/db_utils/workers/services/pulsar.py
import json
from typing import Any, Optional, Union

try:
    import pulsar
    PULSAR_AVAILABLE = hasattr(pulsar, 'Client')
except ImportError:
    pulsar = None
    PULSAR_AVAILABLE = False

from app.core.db_utils.workers.config import worker_settings
from app.logging_config import get_logger

logger = get_logger(__name__)


class PulsarService:
    """A service to manage the Pulsar client, producers, and consumers."""

    def __init__(self, service_url: str):
        self.service_url = service_url
        self._client: Optional[Union[Any, None]] = None
        self._producers: dict[str, Any] = {}

    def get_client(self) -> Any:
        """Get or create the Pulsar client."""
        if not PULSAR_AVAILABLE:
            logger.warning("Pulsar is not available, returning None")
            return None
            
        if self._client is None or self._client.is_closed():
            logger.info(f"Connecting to Pulsar at {self.service_url}")
            try:
                self._client = pulsar.Client(self.service_url)
            except Exception as e:
                logger.error(f"Failed to connect to Pulsar: {e}", exc_info=True)
                raise
        return self._client

    def get_producer(self, topic: str) -> Any:
        """Get a producer for a specific topic, creating it if it doesn't exist."""
        if not PULSAR_AVAILABLE:
            logger.warning("Pulsar is not available, returning None")
            return None
            
        if topic not in self._producers:
            client = self.get_client()
            if client is None:
                return None
            try:
                self._producers[topic] = client.create_producer(topic)
            except Exception as e:
                logger.error(f"Failed to create producer for topic {topic}: {e}", exc_info=True)
                raise
        return self._producers[topic]

    def send_message(self, topic: str, data: dict[str, Any]):
        """Send a message to a specific topic."""
        if not PULSAR_AVAILABLE:
            logger.warning("Pulsar is not available, skipping message send")
            return
            
        producer = self.get_producer(topic)
        if producer is None:
            logger.warning(f"Could not get producer for topic {topic}, skipping message")
            return
            
        try:
            message_content = json.dumps(data).encode("utf-8")
            producer.send(message_content)
            logger.debug(f"Sent message to topic {topic}")
        except Exception as e:
            logger.error(f"Failed to send message to topic {topic}: {e}", exc_info=True)
            raise

    def close(self):
        """Close all producers and the client connection."""
        if not PULSAR_AVAILABLE:
            return
            
        for topic, producer in self._producers.items():
            try:
                if producer is not None:
                    producer.close()
                    logger.info(f"Closed producer for topic {topic}")
            except Exception as e:
                logger.warning(f"Failed to close producer for topic {topic}: {e}", exc_info=True)

        if self._client and not self._client.is_closed():
            try:
                self._client.close()
                logger.info("Pulsar client closed.")
            except Exception as e:
                logger.warning(f"Failed to close Pulsar client: {e}", exc_info=True)
        self._producers.clear()


# Singleton instance of the PulsarService
try:
    pulsar_service = PulsarService(service_url=worker_settings.pulsar_service_url)
except Exception as e:
    logger.warning(f"Failed to initialize Pulsar service: {e}")
    pulsar_service = None
