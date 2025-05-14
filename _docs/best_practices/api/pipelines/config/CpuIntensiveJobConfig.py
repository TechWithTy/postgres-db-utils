"""
CpuIntensiveJobConfig
Production-optimized config for CPU-bound endpoints, using endpoint_configs for per-endpoint logic and global defaults for all others.
- Strict type safety
- Per-endpoint resource, rate limit, cache, etc.
- Ready for FastAPI, Celery, and monitoring integration
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig, EndpointConfig, SecurityConfig
from app.models._data.user.security.role_types import RoleTypeEnum
from app.models._data.user.security.permissions_models import PermissionEnum

# --- CPU-Intensive-specific config types ---
class CpuIntensiveCacheConfig:
    cache_ttl: int = 30
    cache_size: int = 5

class CpuIntensiveRateLimitConfig:
    cpu_task_limit: int = 10
    window_seconds: int = 60

class CpuIntensiveCircuitBreakerConfig:
    circuit_breaker_threshold: int = 2
    circuit_breaker_timeout: int = 60
    max_retries: int = 3
    retry_backoff: int = 5

class CpuIntensiveTracingConfig:
    function_name: str = "cpu_task"
    trace_label: str = "cpu_task_trace"

class CpuIntensiveMetricsConfig:
    cpu_histogram_name: str = "cpu_task_latency_seconds"
    cpu_histogram_description: str = "CPU task latency (seconds)"
    cpu_histogram_label: str = "task_type"

class CpuIntensiveSecurityConfig(SecurityConfig, BaseSettings):
    """
    Security config for CPU-intensive endpoints, loaded from environment variables for production safety.
    All sensitive values should be set via env vars, not hardcoded.
    """
    allowed_roles: list[str] = ["user", "admin"]
    mfa_required: bool = False
    ip_whitelist_enabled: bool = False
    class Config:
        env_prefix = "CPU_"  # e.g., CPU_ALLOWED_ROLES, CPU_MFA_REQUIRED

class CpuIntensiveEncryptionConfig:
    enable_encryption: bool = False
    enable_decryption: bool = False

class CpuIntensiveJobConfig(JobConfig):
    """
    Main config for CPU-intensive endpoints.
    - Per-endpoint resource, cache, rate limit, circuit breaker, tracing, metrics, security, encryption, etc.
    - Global service-level config fields (optional, for legacy or fallback)

    Example usage of RoleTypeEnum and PermissionEnum for endpoint security:

        from app.models._data.user.security.role_types import RoleTypeEnum
        from app.models._data.user.security.permissions_models import PermissionEnum
        ...
        endpoint_configs = {
            "cpu_hash": EndpointConfig(
                auth=SecurityConfig(
                    permission_roles_required=[RoleTypeEnum.user],
                    user_permissions_required=[PermissionEnum.run_cpu],
                    mfa_required=False
                ),
                ...
            ),
            ...
        }
    """
    endpoint_name: str = "cpu_task"
    endpoint_description: str = "CPU-intensive Task Endpoint"
    required_credits: int = 1
    cache: CpuIntensiveCacheConfig = Field(default_factory=CpuIntensiveCacheConfig)
    rate_limit: CpuIntensiveRateLimitConfig = Field(default_factory=CpuIntensiveRateLimitConfig)
    circuit_breaker: CpuIntensiveCircuitBreakerConfig = Field(default_factory=CpuIntensiveCircuitBreakerConfig)
    tracing: CpuIntensiveTracingConfig = Field(default_factory=CpuIntensiveTracingConfig)
    metrics: CpuIntensiveMetricsConfig = Field(default_factory=CpuIntensiveMetricsConfig)
    security: CpuIntensiveSecurityConfig = Field(default_factory=CpuIntensiveSecurityConfig)
    encryption: CpuIntensiveEncryptionConfig = Field(default_factory=CpuIntensiveEncryptionConfig)

    # --- Per-endpoint config: override global defaults as needed ---
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=lambda: {
        "cpu_hash": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=[RoleTypeEnum.user], user_permissions_required=[PermissionEnum.run_cpu], mfa_required=False),
            cache=CpuIntensiveCacheConfig(cache_ttl=10, cache_size=2),
            rate_limit=CpuIntensiveRateLimitConfig(cpu_task_limit=5, window_seconds=60),
            circuit_breaker=CpuIntensiveCircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=CpuIntensiveTracingConfig(function_name="cpu_hash"),
            metrics=CpuIntensiveMetricsConfig(cpu_histogram_name="cpu_hash_latency"),
            security=CpuIntensiveSecurityConfig(allowed_roles=[RoleTypeEnum.user]),
            encryption=CpuIntensiveEncryptionConfig(enable_encryption=False),
            required_credits=1,
            endpoint_name="cpu_hash",
            endpoint_description="CPU hash computation endpoint"
        ),
        "cpu_benchmark": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=[RoleTypeEnum.admin], user_permissions_required=[PermissionEnum.benchmark_cpu], mfa_required=True),
            cache=CpuIntensiveCacheConfig(cache_ttl=2, cache_size=1),
            rate_limit=CpuIntensiveRateLimitConfig(cpu_task_limit=2, window_seconds=120),
            circuit_breaker=CpuIntensiveCircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=CpuIntensiveTracingConfig(function_name="cpu_benchmark"),
            metrics=CpuIntensiveMetricsConfig(cpu_histogram_name="cpu_benchmark_latency"),
            security=CpuIntensiveSecurityConfig(allowed_roles=[RoleTypeEnum.admin], mfa_required=True),
            encryption=CpuIntensiveEncryptionConfig(enable_encryption=False),
            required_credits=2,
            endpoint_name="cpu_benchmark",
            endpoint_description="CPU benchmarking endpoint"
        ),
        "health": EndpointConfig(
            auth=SecurityConfig(permission_roles_required=["guest", "user"], user_permissions_required=[], mfa_required=False),
            cache=CpuIntensiveCacheConfig(cache_ttl=1, cache_size=1),
            tracing=CpuIntensiveTracingConfig(function_name="health"),
            metrics=CpuIntensiveMetricsConfig(cpu_histogram_name="cpu_health_latency"),
            security=CpuIntensiveSecurityConfig(allowed_roles=["guest", "user"]),
            encryption=CpuIntensiveEncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="health",
            endpoint_description="Health check endpoint"
        ),
    })
