# backend/app/core/db_utils/workers/models/task.py
from collections.abc import Callable
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, validator

# Simple credit type enum for worker system
class CreditType(str, Enum):
    """Types of credits that can be consumed by tasks."""
    AI = "ai"
    COMPUTE = "compute" 
    STORAGE = "storage"
    API = "api"


class TaskPriority(str, Enum):
    """Enum for task priorities."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class TaskConfig(BaseModel):
    """
    Configuration model for a TaskRouter task.
    Defines all settings for a task, including API routing, security,
    performance, and credit management.
    """

    # * Core API Route Settings
    name: str = Field(..., description="Unique name for the task, used for routing and logging.")
    description: str | None = Field(None, description="Detailed description for OpenAPI documentation.")
    tags: list[str] = Field(default_factory=list, description="Tags for grouping endpoints in OpenAPI docs.")

    # * Security & RBAC Settings
    required_roles: list[str] = Field(
        default_factory=list, description="List of user roles required to execute the task."
    )

    # * Credit Management Settings
    credit_type: CreditType | None = Field(None, description="The type of credit to charge for this task.")
    credit_cost: int | Callable[[Any], int] = Field(
        1, description="The cost of the task. Can be a fixed integer or a callable function to dynamically estimate the cost."
    )

    # * Rate Limiting
    rate_limit: str | None = Field(None, description="Rate limit for the task, e.g., '100/minute'.")

    # * Pulsar-specific Settings
    topic: str = Field(..., description="The Pulsar topic to which this task's messages will be sent.")
    subscription_name: str | None = Field(None, description="The Pulsar subscription name for the consumer.")
    priority: TaskPriority = Field(TaskPriority.NORMAL, description="The priority of the task.")

    # * Performance & Retry Logic
    timeout: int = Field(30, description="Task execution timeout in seconds.")
    max_retries: int = Field(3, description="Maximum number of retries for a failed task.")
    retry_delay: int = Field(1, description="Delay in seconds between retries.")
    dlq_topic: str | None = Field(None, description="Dead-letter queue topic for messages that fail repeatedly.")

    @validator("credit_cost")
    def validate_credit_cost(cls, v: int | Callable[[Any], int]) -> int | Callable[[Any], int]:
        """Validator to ensure credit cost is non-negative."""
        if isinstance(v, int) and v < 0:
            raise ValueError("Credit cost must be a non-negative integer.")
        return v

    class Config:
        arbitrary_types_allowed = True

