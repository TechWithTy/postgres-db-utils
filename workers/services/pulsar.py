# backend/app/core/db_utils/workers/services/pulsar.py
import json
from typing import Any

import pulsar

from app.core.db_utils.workers.config import worker_settings
from app.logging_config import get_logger

logger = get_logger(__name__)


class PulsarService:
    """A service to manage the Pulsar client, producers, and consumers."""

    def __init__(self, service_url: str):
        self.service_url = service_url
        self._client: pulsar.Client | None = None
        self._producers: dict[str, pulsar.Producer] = {}

    def get_client(self) -> pulsar.Client:
        """Get or create the Pulsar client."""
        if self._client is None or self._client.is_closed():
            logger.info(f"Connecting to Pulsar at {self.service_url}")
            try:
                self._client = pulsar.Client(self.service_url)
            except Exception as e:
                logger.error(f"Failed to connect to Pulsar: {e}", exc_info=True)
                raise
        return self._client

    def get_producer(self, topic: str) -> pulsar.Producer:
        """Get a producer for a specific topic, creating it if it doesn't exist."""
        if topic not in self._producers:
            client = self.get_client()
            try:
                self._producers[topic] = client.create_producer(topic)
            except Exception as e:
                logger.error(f"Failed to create producer for topic {topic}: {e}", exc_info=True)
                raise
        return self._producers[topic]

    def send_message(self, topic: str, data: dict[str, Any]):
        """Send a message to a specific topic."""
        producer = self.get_producer(topic)
        try:
            message_content = json.dumps(data).encode("utf-8")
            producer.send(message_content)
            logger.debug(f"Sent message to topic {topic}")
        except Exception as e:
            logger.error(f"Failed to send message to topic {topic}: {e}", exc_info=True)
            raise

    def close(self):
        """Close all producers and the client connection."""
        for topic, producer in self._producers.items():
            try:
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
pulsar_service = PulsarService(service_url=worker_settings.pulsar_service_url)
