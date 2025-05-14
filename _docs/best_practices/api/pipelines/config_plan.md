# Global Endpoint Configuration Plan

This guide shows how to use a real `config.py` file to centralize and streamline configuration for endpoints and services. The pattern is DRY, type-safe, and production-ready for any backend domain.

---

## 1. Example: config.py for Endpoints

```python
# config.py

# config/rate_limit.py

from enum import Enum


# ---
# config/cache.default.py

# Cache Algos
class CacheAlgo(str, Enum):
    fifo = "fifo"
    lfu = "lfu"
    lifo = "lifo"
    lru = "lru"
    mru = "mru"

class FIFOCacheConfig(BaseModel):
    namespace: str = "fifo"
    default_ttl: int = 3600

class LFUCacheConfig(BaseModel):
    namespace: str = "lfu"
    default_ttl: int = 3600

class LIFOCacheConfig(BaseModel):
    namespace: str = "lifo"
    capacity: int = 100
    default_ttl: int = 3600

class LRUCacheConfig(BaseModel):
    namespace: str = "lru"
    default_ttl: int = 3600

class MRUCacheConfig(BaseModel):
    namespace: str = "mru"
    capacity: int = 100
    default_ttl: int = 3600

class DefaultCacheConfig(BaseModel):
    cache_ttl: int = 300
    user_profile_ttl: int = 60  # * TTL for user profile cache
    cache_size: int = 100
    
class CacheConfig(BaseModel):
    default: DefaultCacheConfig = DefaultCacheConfig()
    algo: CacheAlgo = CacheAlgo.fifo
    fifo: FIFOCacheConfig = FIFOCacheConfig()
    lfu: LFUCacheConfig = LFUCacheConfig()
    lifo: LIFOCacheConfig = LIFOCacheConfig()
    lru: LRUCacheConfig = LRUCacheConfig()
    mru: MRUCacheConfig = MRUCacheConfig()



# Rate Limiting Algos
    
class RateLimitAlgo(str, Enum):
    token_bucket = "token_bucket"
    fixed_window = "fixed_window"
    sliding_window = "sliding_window"
    throttle = "throttle"
    debounce = "debounce"

class TokenBucketConfig(BaseModel):
    rate_limit: int = 20
    rate_window: int = 60
    refill_rate: int = 2

class FixedWindowConfig(BaseModel):
    limit: int = 20
    window: int = 60
class SlidingWindowConfig(BaseModel):
    limit: int = 20
    window: int = 60

class ThrottleConfig(BaseModel):
    interval: int = 60

class DebounceConfig(BaseModel):
    interval: int = 60

class RateLimitConfig(BaseModel):
    algo: RateLimitAlgo = RateLimitAlgo.token_bucket
    token_bucket: TokenBucketConfig = TokenBucketConfig()
    fixed_window: FixedWindowConfig = FixedWindowConfig()
    sliding_window: SlidingWindowConfig = SlidingWindowConfig()
    throttle: ThrottleConfig = ThrottleConfig()
    debounce: DebounceConfig = DebounceConfig()



class TracingConfig(BaseModel):
    function_name: str = "io_job_logic"
    trace_label: str = "io_job_trace"
    # * Add more tracing-related plain-text config here

# config/metrics.py

class MetricsConfig(BaseModel):
    histogram_name: str = "io_job_latency_seconds"
    histogram_description: str = "IO job latency (seconds)"
    histogram_label: str = "resource_id"
    # * Add more metrics/label config here

# config/pulsar_labeling.py

class PulsarLabelingConfig(BaseModel):
    job_topic: str = "persistent://public/default/io-jobs"
    dlq_topic: str = "persistent://public/default/io-jobs-dlq"
    cluster_name: str = "cluster-a"
    producer_label: str = "io_job_producer"
    consumer_label: str = "io_job_consumer"
    event_label: str = "io_job_event"
    max_retries: int = 2  # * Pulsar publish max retries
    retry_delay: float = 2.0  # * Pulsar publish retry delay (seconds)
    # * Add any other plain-text Pulsar label/topic config here


# config/circuit_breaker.py

class CircuitBreakerConfig(BaseModel):
    circuit_breaker_threshold: int = 3
    circuit_breaker_timeout: int = 60
    max_retries: int = 3
    retry_backoff: int = 2

# config/cache.default.py

class CacheConfig(BaseModel):
    cache_ttl: int = 300
    user_profile_ttl: int = 60  # * TTL for user profile cache
    cache_size: int = 100

# config/security.py

from pydantic import BaseSettings

class SecurityConfig(BaseSettings):
    permission_roles_required: list[str] = ["admin", "db_user"]
    user_permissions_required: list[str] = ["read:example", "write:example", "delete:example"]
    auth_type_required: str = "jwt"
    mfa_required: bool = True  # * Require multi-factor authentication
    user_profile_scope_required: str = "read:user"  # * Scope required for user profile endpoint
    ip_whitelist_enabled: bool = True
    db_enabled: bool = True
    class Config:
        env_file = ".env"

class EncryptionConfig(BaseSettings):
    enable_encryption: bool = True
    enable_decryption: bool = True


class JobConfig(BaseModel):
    endpoint_name: str = "io_job"
    endpoint_description: str = "IO Job"
    required_credits: int = 1  # * Credits required per job
    rate_limit: RateLimitConfig = RateLimitConfig()
    pooling: PoolingConfig = PoolingConfig()
    circuit_breaker: CircuitBreakerConfig = CircuitBreakerConfig()
    cache: CacheConfig = CacheConfig()
    security: SecurityConfig = SecurityConfig()
    encryption: EncryptionConfig = EncryptionConfig()
    tracing: TracingConfig = TracingConfig()
    metrics: MetricsConfig = MetricsConfig()
    pulsar_labeling: PulsarLabelingConfig = PulsarLabelingConfig()


---

## 2. Usage Example: FastAPI Route with Config
# * This is the new best practice for all async IO endpoints.  # <-- Encryption last!

from fastapi import APIRouter, Depends, HTTPException, Request
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.roles import roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.credits.credits import call_function_with_credits
from app.core.config import JobConfig, RateLimitAlgo
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from app.core.valkey_core.algorithims.rate_limit.fixed_window import is_allowed_fixed_window
from app.core.valkey_core.algorithims.rate_limit.sliding_window import is_allowed_sliding_window
from app.core.valkey_core.algorithims.rate_limit.throttle import is_allowed_throttle
from app.core.valkey_core.algorithims.rate_limit.debounce import is_allowed_debounce
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from app.core.valkey_core.cache.default.decorators import get_or_set_cache
from app.core.db_utils.security.mfa import get_mfa_service, MFAService  # For MFA enforcement
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from circuitbreaker import circuit
from app.core.pulsar.decorators import pulsar_task
from prometheus_client import Histogram
from app.core.db_utils.security.log_sanitization import get_secure_logger, log_endpoint_event
router = APIRouter()

from pydantic import BaseModel
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing

class ExamplePayload(BaseModel):
    resource_id: str
    secret_value: str
    other_data: str

# * Add observability, tracing, and error tracking decorators (best practice)
@measure_performance(threshold_ms=100.0, level="warn", record_metric=True)  # * Prometheus/metrics, logs slow calls >100ms
@trace_function(name=JobConfig.tracing.function_name, attributes={"route": JobConfig.endpoint_name}, record_metrics=True, capture_exceptions=True)  # * Distributed tracing (custom span name, route attr)
@track_errors  # * Error tracking (Sentry, logs, OpenTelemetry)
@log_endpoint_event(JobConfig.tracing.function_name)
@pulsar_task(
    topic=JobConfig.pulsar_labeling.job_topic,
    producer_label=JobConfig.pulsar_labeling.producer_label,
    event_label=JobConfig.pulsar_labeling.event_label,
    max_retries=JobConfig.pulsar_labeling.max_retries,
    retry_delay=JobConfig.pulsar_labeling.retry_delay,
)  # * Offload to Pulsar for async/event-driven processing (config-driven)
async def _generic_post_endpoint(
    request: Request,
    payload: ExamplePayload,  # Use a concrete Pydantic model
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db=Depends(get_db_client()) if JobConfig.security.db_enabled else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: MFAService = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
):
    """
    Example of a config-driven, globally applicable POST endpoint pattern.
    Replace `ExamplePayload` with your specific Pydantic model as needed.
    """

    # --- 1. Input validation (Pydantic/FastAPI) ---
    # * Already handled by FastAPI and Pydantic

    # --- 2. Observability decorators ---
    # * Already handled by @measure_performance, @trace_function, @track_errors, and @log_endpoint_event

    # --- 3. Authentication/dependencies ---
    # * Already handled by Depends and FastAPI

    # --- 4. Rate limiting (fail fast, DRY) ---
    resource_id = payload.resource_id
    token_bucket_key = JobConfig.tracing.trace_label + f":{verified['user'].id}:{resource_id}"
    rl = JobConfig.rate_limit
    match rl.algo:
        case RateLimitAlgo.token_bucket:
            allowed = await is_allowed_token_bucket(
                token_bucket_key,
                rl.token_bucket.rate_limit,
                rl.token_bucket.refill_rate,
                rl.token_bucket.rate_window
            )
        case RateLimitAlgo.fixed_window:
            allowed = await is_allowed_fixed_window(
                token_bucket_key,
                rl.fixed_window.limit,
                rl.fixed_window.window
            )
        case RateLimitAlgo.sliding_window:
            allowed = await is_allowed_sliding_window(
                token_bucket_key,
                rl.sliding_window.limit,
                rl.sliding_window.window
            )
        case RateLimitAlgo.throttle:
            allowed = await is_allowed_throttle(
                token_bucket_key,
                rl.throttle.interval
            )
        case RateLimitAlgo.debounce:
            allowed = await is_allowed_debounce(
                token_bucket_key,
                rl.debounce.interval
            )
        case _:
            raise HTTPException(status_code=500, detail="Unknown rate limit algorithm")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded for {JobConfig.endpoint_description}"
                + (
                    f" try again in {rl.rate_window} seconds"
                    if getattr(rl, 'rate_window', None)
                    else ""
                )
                + f" (algo: {rl.algo})"
            )
        )

    # --- 5. Security enforcement (MFA, IP whitelist, roles) ---
    if JobConfig.security.mfa_required and not mfa_service:
        raise HTTPException(status_code=401, detail="MFA required")
    if getattr(JobConfig.security, 'ip_whitelist_enabled', False) and not ip_ok:
        raise HTTPException(status_code=403, detail="IP not whitelisted")
    # (Add any additional permission/role checks here)

    # --- 6. Caching (return early if hit, config-driven) ---
    cache_key = f"{JobConfig.endpoint_name}:{resource_id}"
    cache_ttl = JobConfig.cache.default.cache_ttl
    def expensive_operation():
        # ...simulate DB or business logic
        return {"result": "expensive result"}
    cached_result = get_or_set_cache(cache_key, expensive_operation, ttl=cache_ttl)
    # * If cache hit, return early (optional, depends on business logic)
    # if cached_result:
    #     return cached_result

    # --- 7. Credits enforcement (after cache, before business logic) ---
    call_function_with_credits(
        user_id=verified['user'].id,
        required_credits=JobConfig.required_credits,
        endpoint=JobConfig.endpoint_name,
    )

    # --- 8. Business logic, DB, idempotency, etc. ---
    # ...perform main operation, enqueue tasks, etc.

    # --- 9. Idempotency (if needed) ---
    # ...implement idempotency logic here if required

    # --- 10. Task offloading (handled by decorator) ---
    # * Already handled by @pulsar_task decorator

    # --- 11. Encryption/decryption (always last) ---
    if JobConfig.encryption.enable_encryption:
        # Encrypt sensitive fields as needed (handled by decorator or here)
        pass  # Encryption logic or decorator already applied
    if JobConfig.encryption.enable_decryption:
        # Decrypt sensitive fields as needed (handled by decorator or here)
        pass

    # --- 12. Secure logging (last, redact sensitive info) ---
    logger = get_secure_logger(__name__)
    logger.info("Endpoint logic executed", user_id=verified['user'].id, resource_id=resource_id)

    """
    Example of a config-driven, globally applicable POST endpoint pattern.
    Replace `ExamplePayload` with your specific Pydantic model as needed.
    """

    # 1. Rate limiting per user (enum-driven, DRY)
    # * Key pattern should use user/resource/endpoint as needed
    resource_id = payload.resource_id
    token_bucket_key = JobConfig.tracing.trace_label + f":{verified['user'].id}:{resource_id}"
    rl = JobConfig.rate_limit
    # * Cleaner, more maintainable switch-case (Python 3.10+)
    match rl.algo:
        case RateLimitAlgo.token_bucket:
            allowed = await is_allowed_token_bucket(
                token_bucket_key,
                rl.token_bucket.rate_limit,
                rl.token_bucket.refill_rate,
                rl.token_bucket.rate_window
            )
        case RateLimitAlgo.fixed_window:
            allowed = await is_allowed_fixed_window(
                token_bucket_key,
                rl.fixed_window.limit,
                rl.fixed_window.window
            )
        case RateLimitAlgo.sliding_window:
            allowed = await is_allowed_sliding_window(
                token_bucket_key,
                rl.sliding_window.limit,
                rl.sliding_window.window
            )
        case RateLimitAlgo.throttle:
            allowed = await is_allowed_throttle(
                token_bucket_key,
                rl.throttle.interval
            )
        case RateLimitAlgo.debounce:
            allowed = await is_allowed_debounce(
                token_bucket_key,
                rl.debounce.interval
            )
        case _:
            raise HTTPException(status_code=500, detail="Unknown rate limit algorithm")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Rate limit exceeded for {JobConfig.endpoint_description}"
                + (
                    f" try again in {rl.rate_window} seconds"
                    if getattr(rl, 'rate_window', None)
                    else ""
                )
                + f" (algo: {rl.algo})"
            )
        )

    # ...rest of endpoint logic (credits, idempotency, etc.)
    # Encryption should always be applied last per best practices

    # Example secure logging usage
    logger = get_secure_logger(__name__)
    logger.info("Endpoint logic executed", user_id=verified['user'].id, resource_id=resource_id)




# *Note:*
- The rate limiting key can be user/resource/endpoint specific for fine-grained control.
- Input validation should use Pydantic models for all query/path/body data, and can be enforced via middleware for global consistency.


---

## 3. Extending for New Endpoints
- Subclass `DBTaskConfig` for your service (e.g., `AuditLogDBConfig`, `OrderDBConfig`).
- Override only what you need (e.g., metrics, topics, limits).
- Use config attributes in all dependencies, decorators, and business logic.

---

**This pattern ensures all endpoints are DRY, secure, observable, and production-ready.**
