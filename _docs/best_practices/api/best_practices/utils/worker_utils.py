"""
Production-ready, config-driven FastAPI route worker utilities.
Reusable async guards and helpers for endpoints: cache, rate limiting, security, idempotency, tracing, and logging.
"""
from fastapi import Depends, HTTPException, Request
from app.core.db_utils.security.log_sanitization import get_secure_logger
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig, RateLimitAlgo
from app.core.valkey_core.client import ValkeyClient
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from app.core.valkey_core.algorithims.rate_limit.fixed_window import is_allowed_fixed_window
from app.core.valkey_core.algorithims.rate_limit.sliding_window import is_allowed_sliding_window
from app.core.valkey_core.algorithims.rate_limit.throttle import is_allowed_throttle
from app.core.valkey_core.algorithims.rate_limit.debounce import is_allowed_debounce
from app.core.db_utils.security.mfa import get_mfa_service, MFAService
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.security.oauth_scope import require_scope, roles_required
from app.core.db_utils.security.security import get_verified_user
import uuid, json
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import (
    JobConfig
)
import hashlib
from typing import Awaitable, Callable, TypeVar
from fastapi import Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Callable, Awaitable, Any
from app.core.db_utils.credits.credits import deduct_credits_atomic, CreditType
from app.core.db_utils.deps import get_db, get_current_user
from sqlalchemy.orm import Session
from app.core.db_utils.models import User
from typing import Awaitable, Callable, TypeVar
from app.core.db_utils.credits.credits import call_function_with_credits
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing
from app.core.db_utils.deps_supabase import get_current_supabase_user
from fastapi import status
from fastapi import HTTPException
from fastapi import Depends
from fastapi import Request


# --- Cache enforcement dependency ---
async def enforce_cache(
    endpoint_name: str,
    payload: object,
    request: Request,
    cache_backend: ValkeyClient = Depends(lambda: None),
) -> None:
    """
    * Enforce per-endpoint cache policy using config-driven JobConfig.
    * If a cache hit occurs, short-circuit the request and return a 200 with a cache header.
    """
    cache_config = JobConfig.endpoint_configs[endpoint_name].cache
    cache_ttl = getattr(cache_config, 'cache_ttl', 60)
    user_id = getattr(request.state, 'user_id', None)
    # * Compose a cache key based on endpoint, user, and resource
    resource_id = getattr(payload, 'resource_id', None)
    key = f"{endpoint_name}:{user_id}:{resource_id}"
    if not cache_backend:
        raise HTTPException(status_code=500, detail="Cache backend not configured")
    cached = await cache_backend.get(key)
    if cached is not None:
        # ! Cache HIT: return early with header
        raise HTTPException(status_code=200, detail="CACHED", headers={"X-Cache": "HIT"})
    # todo: After endpoint logic, set cache_backend.set(key, result, ex=cache_ttl)

# --- DRY async cache utility ---

T = TypeVar("T")

async def enforce_cache(
    key: str,
    expensive_operation: Callable[[], Awaitable[T]],
    ttl: int,
    cache_backend: ValkeyClient,
) -> T | None:
    """
    * DRY async cache utility: returns cached value if present, otherwise runs expensive_operation and caches the result.
    * Returns None if cache miss and expensive_operation fails.
    """
    cached = await cache_backend.get(key)
    if cached is not None:
        # ! Cache HIT
        return json.loads(cached)
    try:
        result = await expensive_operation()
        await cache_backend.set(key, json.dumps(result), ex=ttl)
        return result
    except Exception as exc:
        logger = get_secure_logger(__name__)
        logger.error("Cache set failed", error=str(exc), cache_key=key)
        return None

# --- DRY async cache utility ---
T = TypeVar("T")

async def enforce_cache(
    key: str,
    expensive_operation: Callable[[], Awaitable[T]],
    ttl: int,
    cache_backend: ValkeyClient,
) -> T | None:
    """
    * DRY async cache utility: returns cached value if present, otherwise runs expensive_operation and caches the result.
    * Returns None if cache miss and expensive_operation fails.
    """
    cached = await cache_backend.get(key)
    if cached is not None:
        # ! Cache HIT
        return json.loads(cached)
    try:
        result = await expensive_operation()
        await cache_backend.set(key, json.dumps(result), ex=ttl)
        return result
    except Exception as exc:
        logger = get_secure_logger(__name__)
        logger.error("Cache set failed", error=str(exc), cache_key=key)
        return None

# --- Credits enforcement utility ---

async def enforce_credits(
    func: Callable[[Request, User], Awaitable[Any]],
    request: Request,
    credit_type: CreditType,  # 'ai', 'leads', or 'skiptrace'
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    credit_amount: int = 1,
) -> JSONResponse:
    """
    FastAPI utility to wrap endpoint logic with credit-based access control.
    Thin wrapper for call_function_with_credits; see that function for full logic.
    """
    return await call_function_with_credits(
        func=func,
        request=request,
        credit_type=credit_type,
        db=db,
        current_user=current_user,
        credit_amount=credit_amount,
    )


# --- Encryption utility ---
def apply_encryption(data: dict) -> dict:
    """
    * DRY utility for applying encryption to a response dict if enabled in JobConfig.
    """
    if JobConfig.encryption.enable_encryption:
        return encrypt_incoming(data)
    return data

# --- Decryption utility ---
def apply_decryption(data: dict) -> dict:
    """
    * DRY utility for applying decryption to a response dict if enabled in JobConfig.
    """
    if JobConfig.encryption.enable_decryption:
        return decrypt_outgoing(data)
    return data

# --- Tracing IDs dependency ---
def get_tracing_ids(request: Request) -> dict:
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response_id = str(uuid.uuid4())
    return {"request_id": request_id, "response_id": response_id}


# --- Security enforcement dependency ---
async def enforce_security(
    verified=Depends(get_verified_user),
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    db=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, "ip_whitelist_enabled", False) else None,
    mfa_service: MFAService = Depends(get_mfa_service) if getattr(JobConfig.security, "mfa_required", False) else None,
) -> None:
    """
    Enforces all configured security controls according to JobConfig.security.
    Raises HTTPException if any requirement is not met.
    """
    if JobConfig.security.mfa_required and not mfa_service:
        raise HTTPException(status_code=401, detail="MFA required")

    if getattr(JobConfig.security, "ip_whitelist_enabled", False) and not ip_ok:
        raise HTTPException(status_code=403, detail="IP not whitelisted")

    if JobConfig.security.permission_roles_required and roles is None:
        raise HTTPException(status_code=403, detail="Insufficient role permissions")

    if JobConfig.security.user_permissions_required and user is None:
        raise HTTPException(status_code=403, detail="Insufficient user permissions")

    # If db is required, ensure it's present (can extend for real DB logic)
    if JobConfig.security.db_enabled and db is None:
        raise HTTPException(status_code=500, detail="Database dependency missing")

# --- Rate limiting dependency ---
async def enforce_rate_limit(
    payload,
    request: Request,
    verified=Depends(get_verified_user),
    tracing_ids: dict = Depends(get_tracing_ids),
):
    resource_id = getattr(payload, "resource_id", None)
    token_bucket_key = JobConfig.tracing.trace_label + f":{verified['user'].id}:{resource_id}"
    rl = JobConfig.rate_limit
    allowed = None
    try:
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
    except Exception as exc:
        logger = get_secure_logger(__name__)
        logger.error("Rate limiting failed", error=str(exc), user_id=verified['user'].id, resource_id=resource_id, request_id=tracing_ids["request_id"], response_id=tracing_ids["response_id"])
        raise HTTPException(status_code=500, detail="Internal rate limiting error")

# --- Idempotency enforcement dependency ---
async def enforce_idempotency(
    request: Request,
    valkey_client: ValkeyClient = Depends(lambda: None),
    tracing_ids: dict = Depends(get_tracing_ids),
):
    idempotency_key = request.headers.get('Idempotency-Key')
    IDEMPOTENCY_TTL = 60
    if idempotency_key and valkey_client:
        try:
            cached_response = await valkey_client.get(idempotency_key)
            if cached_response is not None:
                return json.loads(cached_response)
            await valkey_client.set(idempotency_key, json.dumps({'status': 'processing'}), ex=IDEMPOTENCY_TTL)
        except Exception as exc:
            logger = get_secure_logger(__name__)
            logger.error("Valkey idempotency check failed", error=str(exc), request_id=tracing_ids["request_id"], response_id=tracing_ids["response_id"])
            raise HTTPException(status_code=500, detail="Internal cache error")
    return None
# --- CPU-Intensive Utility ---
def cpu_hash_task(data: str, rounds: int) -> str:
    """
    Simulate CPU-bound work (e.g., repeated SHA-256 hashing).
    ! Do not run this directly in async context; always use a process pool.
    """
    hashed = data.encode()
    for _ in range(rounds):
        hashed = hashlib.sha256(hashed).digest()
    return hashed.hex()

# --- Usage Example ---
# In your route:
# from .worker_utils import enforce_security, enforce_rate_limit, enforce_idempotency, get_tracing_ids
#
# @router.post("/your-endpoint")
# async def your_endpoint(
#     payload: YourPayload,
#     tracing_ids: dict = Depends(get_tracing_ids),
#     _security=Depends(enforce_security),
#     _rate_limit=Depends(enforce_rate_limit),
#     idempotency_result=Depends(enforce_idempotency),
# ):
#     if idempotency_result:
#         return idempotency_result
#     ...
