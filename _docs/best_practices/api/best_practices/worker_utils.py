"""
Production-ready, config-driven FastAPI route worker utilities.
Reusable async guards and helpers for endpoints: rate limiting, security, idempotency, tracing, and logging.
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
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: MFAService = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
):
    if JobConfig.security.mfa_required and not mfa_service:
        raise HTTPException(status_code=401, detail="MFA required")
    if getattr(JobConfig.security, 'ip_whitelist_enabled', False) and not ip_ok:
        raise HTTPException(status_code=403, detail="IP not whitelisted")
    if getattr(JobConfig.security, 'permission_roles_required', None) and roles is not None and not any(role in roles for role in JobConfig.security.permission_roles_required):
        raise HTTPException(status_code=403, detail="Insufficient role permissions")
    if getattr(JobConfig.security, 'user_permissions_required', None) and user is not None and not all(perm in user.get('permissions', []) for perm in JobConfig.security.user_permissions_required):
        raise HTTPException(status_code=403, detail="Insufficient user permissions")

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
