"""
AuthServiceJobConfig
Production-optimized config for authentication-related routes, using endpoint_configs for per-endpoint logic and global defaults for all others.
- Strict type safety
- Per-endpoint auth, rate limit, cache, etc.
- Ready for FastAPI, Celery, and monitoring integration
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig, EndpointConfig, SecurityConfig
from app.models._data.user.security.role_types import RoleTypeEnum
from app.models._data.user.security.permissions_models import PermissionEnum

# --- AuthService-specific config types ---
class AuthServiceCacheConfig:
    cache_ttl: int = 60
    cache_size: int = 20

class AuthServiceRateLimitConfig:
    sign_up_limit: int = 10
    sign_in_limit: int = 20
    reset_password_limit: int = 5
    window_seconds: int = 60

class AuthServiceCircuitBreakerConfig:
    circuit_breaker_threshold: int = 2
    circuit_breaker_timeout: int = 30
    max_retries: int = 2
    retry_backoff: int = 3

class AuthServiceTracingConfig:
    function_name: str = "auth_service_logic"
    trace_label: str = "auth_service_trace"

class AuthServiceMetricsConfig:
    login_histogram_name: str = "auth_login_latency_seconds"
    login_histogram_description: str = "Auth login latency (seconds)"
    login_histogram_label: str = "user_id"
    signup_counter_name: str = "auth_signup_total"

class AuthServiceSecurityConfig(SecurityConfig, BaseSettings):
    """
    Security config for AuthService, loaded from environment variables for production safety.
    All sensitive values should be set via env vars, not hardcoded.
    """
    jwt_secret: str = "changeme"  # fallback for dev ONLY
    session_cookie_name: str = "auth_session"
    password_min_length: int = 8
    password_complexity_regex: str = r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"

    class Config:
        env_prefix = "AUTH_"  # e.g., AUTH_JWT_SECRET, AUTH_SESSION_COOKIE_NAME

class AuthServiceEncryptionConfig:
    enable_encryption: bool = True
    enable_decryption: bool = True

class AuthServiceJobConfig(JobConfig):
    """
    Main config for the authentication service.
    - Per-endpoint authentication, cache, rate limit, circuit breaker, tracing, metrics, security, encryption, etc.
    - Global service-level config fields (optional, for legacy or fallback)
    """
    endpoint_name: str = "auth_service"
    endpoint_description: str = "Authentication Service"
    required_credits: int = 0
    cache: AuthServiceCacheConfig = Field(default_factory=AuthServiceCacheConfig)
    rate_limit: AuthServiceRateLimitConfig = Field(default_factory=AuthServiceRateLimitConfig)
    circuit_breaker: AuthServiceCircuitBreakerConfig = Field(default_factory=AuthServiceCircuitBreakerConfig)
    tracing: AuthServiceTracingConfig = Field(default_factory=AuthServiceTracingConfig)
    metrics: AuthServiceMetricsConfig = Field(default_factory=AuthServiceMetricsConfig)
    security: AuthServiceSecurityConfig = Field(default_factory=AuthServiceSecurityConfig)
    encryption: AuthServiceEncryptionConfig = Field(default_factory=AuthServiceEncryptionConfig)

    # --- Per-endpoint config: override global defaults as needed ---
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=lambda: {
        "sign_up": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.guest],
                user_permissions_required=[],
                mfa_required=False
            ),
            cache=AuthServiceCacheConfig(cache_ttl=10, cache_size=5),
            rate_limit=AuthServiceRateLimitConfig(sign_up_limit=5, window_seconds=60),
            circuit_breaker=AuthServiceCircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=AuthServiceTracingConfig(function_name="sign_up"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="sign_up_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="sign_up",
            endpoint_description="User sign-up endpoint"
        ),
        "sign_in": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.guest, RoleTypeEnum.user],
                user_permissions_required=[],
                mfa_required=False
            ),
            cache=AuthServiceCacheConfig(cache_ttl=5, cache_size=2),
            rate_limit=AuthServiceRateLimitConfig(sign_in_limit=10, window_seconds=60),
            circuit_breaker=AuthServiceCircuitBreakerConfig(circuit_breaker_threshold=1),
            tracing=AuthServiceTracingConfig(function_name="sign_in"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="sign_in_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="sign_in",
            endpoint_description="User sign-in endpoint"
        ),
        "reset_password": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.user],
                user_permissions_required=[PermissionEnum.reset_password],
                mfa_required=True
            ),
            cache=AuthServiceCacheConfig(cache_ttl=1, cache_size=1),
            rate_limit=AuthServiceRateLimitConfig(reset_password_limit=2, window_seconds=300),
            circuit_breaker=AuthServiceCircuitBreakerConfig(circuit_breaker_threshold=2),
            tracing=AuthServiceTracingConfig(function_name="reset_password"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="reset_password_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=True),
            required_credits=0,
            endpoint_name="reset_password",
            endpoint_description="User password reset endpoint"
        ),
        "change_password": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.user, RoleTypeEnum.admin],
                user_permissions_required=[PermissionEnum.change_password],
                mfa_required=True
            ),
            cache=AuthServiceCacheConfig(cache_ttl=1, cache_size=1),
            rate_limit=AuthServiceRateLimitConfig(reset_password_limit=2, window_seconds=300),
            circuit_breaker=AuthServiceCircuitBreakerConfig(circuit_breaker_threshold=2),
            tracing=AuthServiceTracingConfig(function_name="change_password"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="change_password_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=True),
            required_credits=0,
            endpoint_name="change_password",
            endpoint_description="User password change endpoint"
        ),
        "get_user_info": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.user],
                user_permissions_required=[PermissionEnum.read_user],
                mfa_required=False
            ),
            cache=AuthServiceCacheConfig(cache_ttl=60, cache_size=20),
            tracing=AuthServiceTracingConfig(function_name="get_user_info"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="user_info_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=True),
            required_credits=0,
            endpoint_name="get_user_info",
            endpoint_description="Get user info endpoint"
        ),
        "admin_only": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.admin, RoleTypeEnum.super_admin],
                user_permissions_required=[PermissionEnum.admin_all],
                mfa_required=True
            ),
            cache=AuthServiceCacheConfig(cache_ttl=0, cache_size=0),
            tracing=AuthServiceTracingConfig(function_name="admin_only"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="admin_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=True),
            required_credits=0,
            endpoint_name="admin_only",
            endpoint_description="Admin-only endpoint"
        ),
        "health": EndpointConfig(
            auth=SecurityConfig(
                permission_roles_required=[RoleTypeEnum.guest],
                user_permissions_required=[],
                mfa_required=False
            ),
            cache=AuthServiceCacheConfig(cache_ttl=1, cache_size=1),
            tracing=AuthServiceTracingConfig(function_name="health"),
            metrics=AuthServiceMetricsConfig(login_histogram_name="health_latency"),
            security=AuthServiceSecurityConfig(cors_allowed_origins=["*"]),
            encryption=AuthServiceEncryptionConfig(enable_encryption=False),
            required_credits=0,
            endpoint_name="health",
            endpoint_description="Health check endpoint"
        ),
    })
