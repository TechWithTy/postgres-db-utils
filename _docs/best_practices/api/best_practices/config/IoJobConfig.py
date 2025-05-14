"""
IoJobConfig
Production-optimized config for I/O-bound endpoints and jobs, using endpoint_configs for per-endpoint logic and global defaults for all others.
- Strict type safety
- Per-endpoint async I/O, rate limit, cache, etc.
- Ready for FastAPI, Celery, and monitoring integration
- Designed for webhooks, file uploads, external API calls, and other async I/O
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig, EndpointConfig, SecurityConfig
from app.models._data.user.security.role_types import RoleTypeEnum
from app.models._data.user.security.permissions_models import PermissionEnum

# --- IO-specific config types ---
class IoJobCacheConfig:
    cache_ttl: int = 10
    cache_size: int = 10

class IoJobRateLimitConfig:
    io_task_limit: int = 50
    window_seconds: int = 60
    webhook_limit: int = 20
    upload_limit: int = 10

class IoJobCircuitBreakerConfig:
    circuit_breaker_threshold: int = 3
    circuit_breaker_timeout: int = 20
    max_retries: int = 5
    retry_backoff: int = 2

class IoJobTracingConfig:
    function_name: str = "io_task"
    trace_label: str = "io_task_trace"

class IoJobMetricsConfig:
    io_histogram_name: str = "io_task_latency_seconds"
    io_histogram_description: str = "IO task latency (seconds)"
    io_histogram_label: str = "io_type"
    webhook_counter_name: str = "webhook_total"

class IoJobSecurityConfig(SecurityConfig, BaseSettings):
    """
    Security config for IO endpoints, loaded from environment variables for production safety.
    All sensitive values should be set via env vars, not hardcoded.
    """
    allowed_roles: list[str] = ["user", "admin", "webhook"]
    mfa_required: bool = False
    ip_whitelist_enabled: bool = True
    class Config:
        env_prefix = "IO_"  # e.g., IO_ALLOWED_ROLES, IO_MFA_REQUIRED

class IoJobEncryptionConfig:
    enable_encryption: bool = True
    enable_decryption: bool = True

class IoJobConfig(JobConfig):
    """
    Main config for IO-bound endpoints/jobs.
    - Per-endpoint resource, cache, rate limit, circuit breaker, tracing, metrics, security, encryption, etc.
    - Global service-level config fields (optional, for legacy or fallback)

    Example usage of RoleTypeEnum and PermissionEnum for endpoint security:

        from app.models._data.user.security.role_types import RoleTypeEnum
        from app.models._data.user.security.permissions_models import PermissionEnum
        ...
        endpoint_configs = {
            "webhook": EndpointConfig(
                auth=SecurityConfig(
                    permission_roles_required=[RoleTypeEnum.service, RoleTypeEnum.admin],
                    user_permissions_required=[PermissionEnum.create_leads, PermissionEnum.read_report],
                    mfa_required=False
                ),
                ...
            ),
            ...
        }
    """
    endpoint_name: str = "io_task"
    endpoint_description: str = "I/O-bound Task Endpoint"
    required_credits: int = 0
    cache: IoJobCacheConfig = Field(default_factory=IoJobCacheConfig)
    rate_limit: IoJobRateLimitConfig = Field(default_factory=IoJobRateLimitConfig)
    circuit_breaker: IoJobCircuitBreakerConfig = Field(default_factory=IoJobCircuitBreakerConfig)
    tracing: IoJobTracingConfig = Field(default_factory=IoJobTracingConfig)
    metrics: IoJobMetricsConfig = Field(default_factory=IoJobMetricsConfig)
    security: IoJobSecurityConfig = Field(default_factory=IoJobSecurityConfig)
    encryption: IoJobEncryptionConfig = Field(default_factory=IoJobEncryptionConfig)

    # --- Per-endpoint config: override global defaults as needed ---
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=lambda: {
        "webhook": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=[RoleTypeEnum.service], user_permissions_required=[PermissionEnum.create_leads], mfa_required=False),
            cache=IoJobCacheConfig(cache_ttl=2, cache_size=2),
            rate_limit=IoJobRateLimitConfig(webhook_limit=10, window_seconds=60),
            circuit_breaker=IoJobCircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=IoJobTracingConfig(function_name="webhook"),
            metrics=IoJobMetricsConfig(io_histogram_name="webhook_latency"),
            security=IoJobSecurityConfig(allowed_roles=[RoleTypeEnum.service]),
            encryption=IoJobEncryptionConfig(enable_encryption=True),
            required_credits=0,
            endpoint_name="webhook",
            endpoint_description="Webhook endpoint"
        ),
        "file_upload": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["user"], user_permissions_required=["upload:file"], mfa_required=True),
            cache=IoJobCacheConfig(cache_ttl=5, cache_size=3),
            rate_limit=IoJobRateLimitConfig(upload_limit=5, window_seconds=60),
            circuit_breaker=IoJobCircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=IoJobTracingConfig(function_name="file_upload"),
            metrics=IoJobMetricsConfig(io_histogram_name="file_upload_latency"),
            security=IoJobSecurityConfig(allowed_roles=["user"], mfa_required=True),
            encryption=IoJobEncryptionConfig(enable_encryption=True),
            required_credits=1,
            endpoint_name="file_upload",
            endpoint_description="File upload endpoint"
        ),
        "external_api_call": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["user", "admin"], user_permissions_required=["call:external_api"], mfa_required=False),
            cache=IoJobCacheConfig(cache_ttl=1, cache_size=1),
            rate_limit=IoJobRateLimitConfig(io_task_limit=10, window_seconds=30),
            circuit_breaker=IoJobCircuitBreakerConfig(circuit_breaker_threshold=2),
            tracing=IoJobTracingConfig(function_name="external_api_call"),
            metrics=IoJobMetricsConfig(io_histogram_name="external_api_call_latency"),
            security=IoJobSecurityConfig(allowed_roles=["user", "admin"]),
            encryption=IoJobEncryptionConfig(enable_encryption=True),
            required_credits=1,
            endpoint_name="external_api_call",
            endpoint_description="External API call endpoint"
        ),
        "health": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["guest", "user", "webhook"], user_permissions_required=[], mfa_required=False),
            cache=IoJobCacheConfig(cache_ttl=1, cache_size=1),
            tracing=IoJobTracingConfig(function_name="health"),
            metrics=IoJobMetricsConfig(io_histogram_name="io_health_latency"),
            security=IoJobSecurityConfig(allowed_roles=["guest", "user", "webhook"]),
            encryption=IoJobEncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="health",
            endpoint_description="Health check endpoint"
        ),
    })
