from app.models.credit import CreditType
from pydantic import BaseModel
from typing import Literal


class IOTaskConfig(BaseModel):
    """Configuration model for I/O task settings with best practices.
    All fields are optional and default to None if not provided.
    """

    credit_type: CreditType | None = None
    credit_amount: int | None = None
    auth_type: Literal["jwt", "api_key", "oauth", "none"] = "none"
    cache_ttl: int = 300  # 5 minutes
    rate_limit: int = 100
    rate_window: int = 60  # 1 minute
    max_retries: int = 3
    backoff: int = 2
    task_timeout: int = 60  # in seconds
    endpoint: str = "io-task"
    task_priority: int = 5
    permission_roles: list[str] | None = (
        None  # Optionally restricts task execution to these roles (e.g., ["user", "admin"])
    )


class DBTaskConfig(BaseModel):
    """Configuration model for DB task settings with best practices.
    All fields are optional and default to None if not provided.
    """

    credit_type: CreditType | None = None
    credit_amount: int | None = None
    auth_type: Literal["jwt", "api_key", "oauth", "none"] = "none"
    cache_ttl: int = 300  # 5 minutes
    rate_limit: int = 100
    rate_window: int = 60  # 1 minute
    max_retries: int = 3
    backoff: int = 2
    task_timeout: int = 120  # in seconds
    endpoint: str = "db-task"
    task_priority: int = 5
    permission_roles: list[str] | None = (
        None  # Optionally restricts task execution to these roles (e.g., ["user", "admin"])
    )


class CPUTaskConfig(BaseModel):
    """Configuration model for CPU task settings with best practices.
    All fields are optional and default to None if not provided.
    """

    credit_type: CreditType | None = None
    credit_amount: int | None = None
    auth_type: Literal["jwt", "api_key", "oauth", "none"] = "none"
    cache_ttl: int = 300  # 5 minutes
    rate_limit: int = 100
    rate_window: int = 60  # 1 minute
    auto_estimate_credits: bool = True
    max_retries: int = 3
    backoff: int = 2
    cb_threshold: int = 100
    cb_timeout: int = 60  # in seconds
    task_timeout: int = 60  # in seconds
    endpoint: str = "cpu-task"
    task_priority: int = 5
    permission_roles: list[str] | None = (
        None  # Optionally restricts task execution to these roles (e.g., ["user", "admin"])
    )


class PulsarIOTaskConfig(IOTaskConfig):
    """
    Pulsar configuration for I/O tasks.
    Inherits all IOTaskConfig fields and adds Pulsar-specific options for Pulsar-based async execution.
    Use this configuration for I/O tasks when using Pulsar.
    """
    topic: str | None = None  # Pulsar topic for the task
    dlq_topic: str | None = None  # Dead-letter queue topic for failed tasks


class PulsarDBTaskConfig(DBTaskConfig):
    """
    Pulsar configuration for DB tasks.
    Inherits all DBTaskConfig fields and adds Pulsar-specific options.
    """

    topic: str | None = None  # Pulsar topic for the task
    dlq_topic: str | None = None  # Dead-letter queue topic for failed tasks


class PulsarCPUTaskConfig(CPUTaskConfig):
    """
    Pulsar configuration for CPU tasks.
    Inherits all CPUTaskConfig fields and adds Pulsar-specific options.
    """

    topic: str | None = None  # Pulsar topic for the task
    dlq_topic: str | None = None  # Dead-letter queue topic for failed tasks
