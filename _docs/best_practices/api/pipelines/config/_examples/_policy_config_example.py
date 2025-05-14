"""
Concrete Example: JobConfig for Per-Endpoint Policy Enforcement

This file demonstrates how to define a JobConfig with endpoint-specific policy settings,
enabling or disabling policies and customizing their parameters per endpoint.
"""
from pydantic import BaseModel
from typing import Optional

# --- Policy Config Models ---
class CachePolicyConfig(BaseModel):
    enabled: bool = True
    ttl_seconds: int = 60

class RateLimitPolicyConfig(BaseModel):
    enabled: bool = True
    sign_in_limit: int = 10
    window_seconds: int = 60

class CircuitBreakerPolicyConfig(BaseModel):
    enabled: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 30

class TracingPolicyConfig(BaseModel):
    enabled: bool = True
    function_name: str = "user_profile"
    trace_label: Optional[str] = None

class MetricsPolicyConfig(BaseModel):
    enabled: bool = True
    login_histogram_name: str = "user_login_latency"
    signup_counter_name: str = "user_signup_total"

class SecurityPolicyConfig(BaseModel):
    enabled: bool = True
    allowed_origins: list[str] = ["*"]

class EncryptionPolicyConfig(BaseModel):
    enabled: bool = False
    enable_encryption: bool = False
    enable_decryption: bool = False

# --- Endpoint Config ---
class EndpointConfig(BaseModel):
    cache: CachePolicyConfig = CachePolicyConfig()
    rate_limit: RateLimitPolicyConfig = RateLimitPolicyConfig()
    circuit_breaker: CircuitBreakerPolicyConfig = CircuitBreakerPolicyConfig()
    tracing: TracingPolicyConfig = TracingPolicyConfig()
    metrics: MetricsPolicyConfig = MetricsPolicyConfig()
    security: SecurityPolicyConfig = SecurityPolicyConfig()
    encryption: EncryptionPolicyConfig = EncryptionPolicyConfig()

# --- JobConfig Example ---
class JobConfig(BaseModel):
    endpoint_configs: dict[str, EndpointConfig] = {
        "user_profile": EndpointConfig(
            cache=CachePolicyConfig(enabled=True, ttl_seconds=120),
            rate_limit=RateLimitPolicyConfig(enabled=True, sign_in_limit=5, window_seconds=30),
            circuit_breaker=CircuitBreakerPolicyConfig(enabled=True, circuit_breaker_threshold=3, circuit_breaker_timeout=20),
            tracing=TracingPolicyConfig(enabled=True, function_name="user_profile", trace_label="UserProfileTrace"),
            metrics=MetricsPolicyConfig(enabled=True, login_histogram_name="login_latency", signup_counter_name="signup_total"),
            security=SecurityPolicyConfig(enabled=True, allowed_origins=["https://app.example.com"]),
            encryption=EncryptionPolicyConfig(enabled=False),
        ),
        "admin_dashboard": EndpointConfig(
            cache=CachePolicyConfig(enabled=False),
            rate_limit=RateLimitPolicyConfig(enabled=True, sign_in_limit=2, window_seconds=60),
            circuit_breaker=CircuitBreakerPolicyConfig(enabled=True, circuit_breaker_threshold=2, circuit_breaker_timeout=60),
            tracing=TracingPolicyConfig(enabled=True, function_name="admin_dashboard"),
            metrics=MetricsPolicyConfig(enabled=True, login_histogram_name="admin_login_latency", signup_counter_name="admin_signup_total"),
            security=SecurityPolicyConfig(enabled=True, allowed_origins=["https://admin.example.com"]),
            encryption=EncryptionPolicyConfig(enabled=True, enable_encryption=True, enable_decryption=True),
        ),
    }
    default_endpoint_config: EndpointConfig = EndpointConfig()

"""
USAGE PATTERN: Per-Endpoint Policy Enforcement in FastAPI

Best practice: Attach enforce_all_policies(endpoint_name, config) to each route with the correct endpoint_name.
This ensures each route gets its own config-driven policy enforcement.

If an endpoint_name is not found in config.endpoint_configs, the default_endpoint_config is used as a fallback.
You can make this strict by raising an error if endpoint_name is missing.
"""

from ._policy_config_example import JobConfig
from app.core.db_utils._docs.best_practices.api.pipelines.utils.policies import enforce_all_policies
from fastapi import APIRouter

config = JobConfig()
router = APIRouter()

# --- Example: Attach per-endpoint policy enforcement ---
user_profile_policy = enforce_all_policies("user_profile", config)
admin_dashboard_policy = enforce_all_policies("admin_dashboard", config)

@router.post("/user_profile", dependencies=[user_profile_policy])
async def user_profile():
    ...

@router.post("/admin_dashboard", dependencies=[admin_dashboard_policy])
async def admin_dashboard():
    ...

# --- Optional: Strict enforcement (raise if endpoint not found) ---
def enforce_all_policies_strict(endpoint_name: str, config: JobConfig):
    if endpoint_name not in config.endpoint_configs:
        raise RuntimeError(f"Endpoint '{endpoint_name}' missing from config.endpoint_configs!")
    return enforce_all_policies(endpoint_name, config)

# Example usage:
# enforce_all_policies_strict("user_profile", config)
