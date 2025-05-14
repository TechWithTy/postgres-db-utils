import uuid
from app.core.db_utils.deps_supabase import get_current_supabase_user
from fastapi import status
from fastapi import HTTPException
from fastapi import Depends
from fastapi import Request
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import (
    JobConfig
    
)   



# --- Cache Enforcement Dependency ---
async def enforce_cache_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    cache_backend=None,  # e.g., ValkeyClient instance injected at app startup
    request: Request = None,
) -> None:
    """
    Enforce the per-endpoint cache policy using config-driven JobConfig.
    This checks if the result is cached; if not, it allows the handler to proceed and caches the result after.
    """
    cache_config = config.endpoint_configs[endpoint_name].cache
    if not cache_backend:
        raise HTTPException(status_code=500, detail="Cache backend not configured")
    # Compose a cache key based on endpoint, user, and request params
    user_id = getattr(request.state, 'user_id', None)
    key = f"{endpoint_name}:{user_id}:{request.url.path}:{request.url.query}"
    cached = await cache_backend.get(key)
    if cached is not None:
        # Optionally, short-circuit and return cached response
        raise HTTPException(status_code=200, detail="CACHED", headers={"X-Cache": "HIT"})
    # If not cached, handler proceeds; after response, cache should be set (see decorator pattern)

# --- Rate Limiting Enforcement Dependency ---
async def enforce_rate_limit_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    rate_limit_backend=None,  # e.g., ValkeyClient instance injected at app startup
    request: Request = None,
) -> None:
    """
    Enforce the per-endpoint rate limit policy using config-driven JobConfig.
    Uses token bucket or fixed window depending on backend implementation.
    """
    rate_limit_config = config.endpoint_configs[endpoint_name].rate_limit
    if not rate_limit_backend:
        raise HTTPException(status_code=500, detail="Rate limit backend not configured")
    user_id = getattr(request.state, 'user_id', None)
    key = f"rate_limit:{endpoint_name}:{user_id}:{request.client.host}"
    allowed = await rate_limit_backend.is_allowed(
        key,
        limit=rate_limit_config.sign_in_limit,
        window=rate_limit_config.window_seconds
    )
    if not allowed:
        raise HTTPException(status_code=429, detail="Too Many Requests", headers={"Retry-After": str(rate_limit_config.window_seconds)})

# --- Circuit Breaker Enforcement Dependency ---
async def enforce_circuit_breaker_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    circuit_breaker_backend=None,  # e.g., circuitbreaker lib, Redis, or custom
    request: Request = None,
) -> None:
    """
    Enforce the per-endpoint circuit breaker policy using config-driven JobConfig.
    If the circuit is open, short-circuit the request; otherwise, allow to proceed.
    """
    cb_config = config.endpoint_configs[endpoint_name].circuit_breaker
    if not circuit_breaker_backend:
        raise HTTPException(status_code=500, detail="Circuit breaker backend not configured")
    user_id = getattr(request.state, 'user_id', None)
    key = f"cb:{endpoint_name}:{user_id}:{request.client.host}"
    is_open = await circuit_breaker_backend.is_circuit_open(
        key,
        threshold=cb_config.circuit_breaker_threshold,
        timeout=cb_config.circuit_breaker_timeout
    )
    if is_open:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable (circuit open)")




# --- Tracing Enforcement Dependency ---
async def enforce_tracing_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    tracing_backend=None,  # e.g., OpenTelemetry, custom
    request: Request = None,
) -> None:
    """
    Enforce per-endpoint tracing policy using config-driven JobConfig.
    Adds trace info (function name, label) to tracing backend.
    """
    tracing_config = config.endpoint_configs[endpoint_name].tracing
    if not tracing_backend:
        raise HTTPException(status_code=500, detail="Tracing backend not configured")
    await tracing_backend.start_trace(
        function_name=tracing_config.function_name,
        trace_label=getattr(tracing_config, 'trace_label', endpoint_name),
        request=request,
    )

# --- Metrics Enforcement Dependency ---
async def enforce_metrics_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    metrics_backend=None,  # e.g., Prometheus, custom
    request: Request = None,
) -> None:
    """
    Enforce per-endpoint metrics policy using config-driven JobConfig.
    Records latency, counters, etc. based on config.
    """
    metrics_config = config.endpoint_configs[endpoint_name].metrics
    if not metrics_backend:
        raise HTTPException(status_code=500, detail="Metrics backend not configured")
    await metrics_backend.record_histogram(
        metrics_config.login_histogram_name,
        value=getattr(request.state, 'latency', 0),
        labels={"endpoint": endpoint_name}
    )
    await metrics_backend.increment_counter(metrics_config.signup_counter_name, labels={"endpoint": endpoint_name})

# --- Security Enforcement Dependency ---
async def enforce_security_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    security_backend=None,  # e.g., CORS/CSRF middleware, custom
    request: Request = None,
) -> None:
    """
    Enforce per-endpoint security policy using config-driven JobConfig.
    Applies CORS/CSRF or other security headers/policies.
    """
    security_config = config.endpoint_configs[endpoint_name].security
    if not security_backend:
        raise HTTPException(status_code=500, detail="Security backend not configured")
    await security_backend.apply_policy(request, security_config)

# --- Encryption Enforcement Dependency ---
async def enforce_encryption_policy(
    endpoint_name: str,
    config: JobConfig = Depends(),
    encryption_backend=None,  # e.g., Fernet, custom
    request: Request = None,
    payload=None,
) -> None:
    """
    Enforce per-endpoint encryption policy using config-driven JobConfig.
    Encrypts/decrypts payloads if enabled in config.
    """
    encryption_config = config.endpoint_configs[endpoint_name].encryption
    if not encryption_backend:
        raise HTTPException(status_code=500, detail="Encryption backend not configured")
    if encryption_config.enable_encryption:
        if payload is not None:
            request.state.encrypted_payload = await encryption_backend.encrypt(payload)
    if encryption_config.enable_decryption:
        if hasattr(request.state, 'encrypted_payload'):
            request.state.decrypted_payload = await encryption_backend.decrypt(request.state.encrypted_payload)

# --- Centralized Policy Enforcement Mapping ---
POLICY_ENFORCEMENT_MAP = {
    "cache": enforce_cache_policy,
    "rate_limit": enforce_rate_limit_policy,
    "circuit_breaker": enforce_circuit_breaker_policy,
    "tracing": enforce_tracing_policy,
    "metrics": enforce_metrics_policy,
    "security": enforce_security_policy,
    "encryption": enforce_encryption_policy,
}

# * Usage Example:
# for policy, enforce_fn in POLICY_ENFORCEMENT_MAP.items():
#     if config.endpoint_configs[endpoint_name].get(policy):
#         await enforce_fn(endpoint_name, config, ...)
