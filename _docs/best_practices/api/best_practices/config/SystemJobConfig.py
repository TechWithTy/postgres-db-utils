"""
SystemJobConfig
Production-optimized config for system-level routes, using endpoint_configs for per-endpoint logic and global defaults for all others.
- Strict type safety
- Per-endpoint auth, rate limit, cache, etc.
- Ready for FastAPI, Celery, and monitoring integration
"""

from pydantic import Field
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig, EndpointConfig, SecurityConfig, CacheConfig, RateLimitConfig, CircuitBreakerConfig, TracingConfig, MetricsConfig, EncryptionConfig

class SystemJobConfig(JobConfig):
    """
    SystemJobConfig for all system routes.
    - Use endpoint_configs to specify per-route logic.
    - Global defaults (cache, rate_limit, etc.) apply to all endpoints unless overridden.
    """
    endpoint_name: str = "system_job"
    endpoint_description: str = "System-level Job Endpoint"
    required_credits: int = 0
    # System-specific global defaults (optional)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    tracing: TracingConfig = Field(default_factory=TracingConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)

    # --- Per-endpoint config: override global defaults as needed ---
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=lambda: {
        "system_health": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["system", "admin"], user_permissions_required=["read:system"], mfa_required=False),
            cache=CacheConfig(cache_ttl=30, cache_size=5),
            rate_limit=RateLimitConfig(limit=50, window_seconds=10),
            circuit_breaker=CircuitBreakerConfig(circuit_breaker_threshold=3),
            tracing=TracingConfig(function_name="system_health"),
            metrics=MetricsConfig(histogram_name="system_health_latency"),
            security=SecurityConfig(permission_roles_required=["system"]),
            encryption=EncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="system_health",
            endpoint_description="Check system health"
        ),
        "system_restart": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["admin"], user_permissions_required=["restart:system"], mfa_required=True),
            cache=CacheConfig(cache_ttl=0, cache_size=1),
            rate_limit=RateLimitConfig(limit=1, window_seconds=300),
            circuit_breaker=CircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=TracingConfig(function_name="system_restart"),
            metrics=MetricsConfig(histogram_name="system_restart_latency"),
            security=SecurityConfig(permission_roles_required=["admin"]),
            encryption=EncryptionConfig(enable_encryption=True),
            required_credits=2,
            endpoint_name="system_restart",
            endpoint_description="Restart the system (admin only)"
        ),
    })
