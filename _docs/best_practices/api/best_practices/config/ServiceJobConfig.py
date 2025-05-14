"""
ServiceJobConfig
Production-optimized config for service-level routes, using endpoint_configs for per-endpoint logic and global defaults for all others.
- Strict type safety
- Per-endpoint auth, rate limit, cache, etc.
- Ready for FastAPI, Celery, and monitoring integration
"""

from pydantic import Field
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig, EndpointConfig, SecurityConfig, CacheConfig, RateLimitConfig, CircuitBreakerConfig, TracingConfig, MetricsConfig, EncryptionConfig

class ServiceJobConfig(JobConfig):
    """
    ServiceJobConfig for all service routes.
    - Use endpoint_configs to specify per-route logic.
    - Global defaults (cache, rate_limit, etc.) apply to all endpoints unless overridden.
    """
    endpoint_name: str = "service_job"
    endpoint_description: str = "Service-level Job Endpoint"
    required_credits: int = 0
    # Service-specific global defaults (optional)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)

    # --- Per-endpoint config: override global defaults as needed ---
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=lambda: {
        "service_status": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["service", "admin"], user_permissions_required=["read:service"], mfa_required=False),
            cache=CacheConfig(cache_ttl=60, cache_size=10),
            rate_limit=RateLimitConfig(limit=20, window_seconds=30),
            circuit_breaker=CircuitBreakerConfig(circuit_breaker_threshold=2),
            tracing=TracingConfig(function_name="service_status"),
            metrics=MetricsConfig(histogram_name="service_status_latency"),
            security=SecurityConfig(permission_roles_required=["service"]),
            encryption=EncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="service_status",
            endpoint_description="Check service status"
        ),
        "service_action": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["admin"], user_permissions_required=["write:service"], mfa_required=True),
            cache=CacheConfig(cache_ttl=10, cache_size=5),
            rate_limit=RateLimitConfig(limit=5, window_seconds=60),
            circuit_breaker=CircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=TracingConfig(function_name="service_action"),
            metrics=MetricsConfig(histogram_name="service_action_latency"),
            security=SecurityConfig(permission_roles_required=["admin"]),
            encryption=EncryptionConfig(enable_encryption=True),
            required_credits=1,
            endpoint_name="service_action",
            endpoint_description="Perform a privileged service action"
        ),
    })
