# backend/app/core/db_utils/workers/config.py
from pydantic import Field
from pydantic_settings import BaseSettings


class WorkerSettings(BaseSettings):
    """Configuration settings for the TaskRouter workers."""

    pulsar_service_url: str = Field(
        "pulsar://localhost:6650",
        description="URL for the Pulsar service.",
        env="PULSAR_SERVICE_URL",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


worker_settings = WorkerSettings()
