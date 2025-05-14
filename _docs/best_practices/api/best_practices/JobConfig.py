

# config.py

# config/rate_limit.py

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field
from pydantic import BaseSettings


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

class EndpointConfig(BaseModel):
    auth: SecurityConfig
    cache: CacheConfig | None = None
    rate_limit: RateLimitConfig | None = None
    circuit_breaker: CircuitBreakerConfig | None = None
    tracing: TracingConfig | None = None
    metrics: MetricsConfig | None = None
    security: SecurityConfig | None = None
    encryption: EncryptionConfig | None = None
    required_credits: int = 0
    endpoint_name: str | None = None
    endpoint_description: str | None = None

class JobConfig(BaseModel):
    """
    Base config for all jobs/services.
    - Supports per-endpoint logic via endpoint_configs (auth, rate limit, etc.)
    - Each endpoint should be explicitly configured; global defaults apply if not set per-endpoint.
    """
    model_config = ConfigDict(extra="forbid")
    endpoint_name: str = "io_job"
    endpoint_description: str = "IO Job"
    required_credits: int = 1  # * Credits required per job
    rate_limit: RateLimitConfig = RateLimitConfig()
    circuit_breaker: CircuitBreakerConfig = CircuitBreakerConfig()
    cache: CacheConfig = CacheConfig()
    security: SecurityConfig = SecurityConfig()
    encryption: EncryptionConfig = EncryptionConfig()
    tracing: TracingConfig = TracingConfig()
    metrics: MetricsConfig = MetricsConfig()
    pulsar_labeling: PulsarLabelingConfig = PulsarLabelingConfig()
    # --- Per-endpoint config: all endpoint-specific logic goes here ---
    endpoint_configs: dict[str, EndpointConfig] = Field(default_factory=dict)


