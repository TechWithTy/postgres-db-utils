"""
Production-ready, config-driven FastAPI endpoint example.
Order and comments follow best practices for async IO endpoints, security, and observability.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.oauth_scope import roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.credits.credits import call_function_with_credits
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig, RateLimitAlgo
from app.core.valkey_core.algorithims.rate_limit.token_bucket import is_allowed_token_bucket
from app.core.valkey_core.algorithims.rate_limit.fixed_window import is_allowed_fixed_window
from app.core.valkey_core.algorithims.rate_limit.sliding_window import is_allowed_sliding_window
from app.core.valkey_core.algorithims.rate_limit.throttle import is_allowed_throttle
from app.core.valkey_core.algorithims.rate_limit.debounce import is_allowed_debounce
from app.core.valkey_core.cache.decorators import get_or_set_cache
from app.core.db_utils.security.mfa import get_mfa_service, MFAService
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from typing import Any
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing
import json
from app.core.pulsar.decorators import pulsar_task
from app.core.db_utils.security.log_sanitization import get_secure_logger, log_endpoint_event
import uuid
router = APIRouter()

from app.core.valkey_core.client import ValkeyClient
# Dependency-injected async Valkey client (production best practice)
async def get_valkey_client() -> ValkeyClient:
    from app.core.valkey_core.client import client
    return client

class ExamplePayload(BaseModel):
    resource_id: str
    secret_value: str
    other_data: str

class ExampleSuccessResponse(BaseModel):
    success: bool
    message: str
    data: dict

class ExampleErrorResponse(BaseModel):
    detail: str

@measure_performance(threshold_ms=100.0, level="warn", record_metric=True)
@trace_function(name=JobConfig.tracing.function_name, attributes={"route": JobConfig.endpoint_name}, record_metrics=True, capture_exceptions=True)
@track_errors
@log_endpoint_event(JobConfig.tracing.function_name)
@pulsar_task(
    topic=JobConfig.pulsar_labeling.job_topic,
    producer_label=JobConfig.pulsar_labeling.producer_label,
    event_label=JobConfig.pulsar_labeling.event_label,
    max_retries=JobConfig.pulsar_labeling.max_retries,
    retry_delay=JobConfig.pulsar_labeling.retry_delay,
)
async def generic_post_endpoint(
    payload: ExamplePayload,
    request: Request,
    valkey_client: ValkeyClient = Depends(get_valkey_client),  # ! Injected async Valkey client
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: MFAService = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
) -> ExampleSuccessResponse:
    # --- Tracing IDs ---
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response_id = str(uuid.uuid4())

    """
    Config-driven, production-ready POST endpoint pattern.
    Replace ExamplePayload with your Pydantic model as needed.
    """
    # --- 1. Input validation (Pydantic/FastAPI) ---
    # * Already handled by FastAPI and Pydantic

    # --- 2. Observability decorators ---
    # * Already handled by decorators above

    # --- 3. Authentication/dependencies ---
    # * Already handled by Depends

    # --- 4. Rate limiting (fail fast, DRY) ---
    resource_id = payload.resource_id
    token_bucket_key = JobConfig.tracing.trace_label + f":{verified['user'].id}:{resource_id}"
    rl = JobConfig.rate_limit
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
        logger.error("Rate limiting failed", error=str(exc), user_id=verified['user'].id, resource_id=resource_id, request_id=request_id, response_id=response_id)
        raise HTTPException(status_code=500, detail="Internal rate limiting error")

    # --- 5. Security enforcement (MFA, IP whitelist, roles/permissions) ---
    if JobConfig.security.mfa_required and not mfa_service:
        raise HTTPException(status_code=401, detail="MFA required")
    if getattr(JobConfig.security, 'ip_whitelist_enabled', False) and not ip_ok:
        raise HTTPException(status_code=403, detail="IP not whitelisted")
    if getattr(JobConfig.security, 'permission_roles_required', None) and roles is not None and not any(role in roles for role in JobConfig.security.permission_roles_required):
        raise HTTPException(status_code=403, detail="Insufficient role permissions")
    if getattr(JobConfig.security, 'user_permissions_required', None) and user is not None and not all(perm in user.get('permissions', []) for perm in JobConfig.security.user_permissions_required):
        raise HTTPException(status_code=403, detail="Insufficient user permissions")

    # --- 6. Idempotency enforcement (Valkey/Redis, async, production-ready) ---
    idempotency_key = request.headers.get('Idempotency-Key')
    IDEMPOTENCY_TTL = 60  # seconds
    if idempotency_key:
        try:
            # Check if key exists (duplicate request)
            cached_response = await valkey_client.get(idempotency_key)
            if cached_response is not None:
                # * Return cached response (deserialize if needed)
                return json.loads(cached_response)
            # Mark as processing (setex with short TTL)
            await valkey_client.set(idempotency_key, json.dumps({'status': 'processing'}), ex=IDEMPOTENCY_TTL)
        except Exception as exc:
            logger = get_secure_logger(__name__)
            logger.error("Valkey idempotency check failed", error=str(exc), user_id=verified['user'].id, resource_id=resource_id, request_id=request_id, response_id=response_id)
            raise HTTPException(status_code=500, detail="Internal cache error")

    # --- 7. Caching (return early if hit, config-driven) ---
    cache_key = f"{JobConfig.endpoint_name}:{resource_id}"
    cache_ttl = JobConfig.cache.default.cache_ttl
    def expensive_operation():
        # ...simulate DB or business logic
        return {"result": "expensive result", "success": True}
    try:
        cached_result = await get_or_set_cache(cache_key, expensive_operation, ttl=cache_ttl)
        # * If cache hit, return early (recommended for DRY/efficiency)
        if cached_result:
            return cached_result
    except Exception as exc:
        logger = get_secure_logger(__name__)
        logger.error("Cache retrieval failed", error=str(exc), user_id=verified['user'].id, resource_id=resource_id, request_id=request_id, response_id=response_id)
        raise HTTPException(status_code=500, detail="Internal cache error")

    # --- 8. Business logic, DB, idempotency, etc. ---
    # ...perform main operation, enqueue tasks, etc.
    # For demonstration, simulate a business result:
    business_result = {"success": True, "message": "Operation completed", "data": {"resource_id": resource_id}}

    # --- 9. Credits enforcement (only on success) ---
    if business_result.get("success"):
        try:
            call_function_with_credits(
                user_id=verified['user'].id,
                required_credits=JobConfig.required_credits,
                endpoint=JobConfig.endpoint_name,
            )
        except Exception as exc:
            logger = get_secure_logger(__name__)
            logger.error("Credits deduction failed", error=str(exc), user_id=verified['user'].id, resource_id=resource_id, request_id=request_id, response_id=response_id)
            raise HTTPException(status_code=500, detail="Internal credits error")

    # --- 10. Encryption/decryption (always last) ---
    if JobConfig.encryption.enable_encryption:
        business_result = encrypt_incoming(business_result)
    if JobConfig.encryption.enable_decryption:
        business_result = decrypt_outgoing(business_result)

    # --- 11. Secure logging (last, redact sensitive info) ---
    logger = get_secure_logger(__name__)
    logger.info("Endpoint logic executed", user_id=verified['user'].id, resource_id=resource_id, request_id=request_id, response_id=response_id)

    # Attach tracing IDs to response
    business_result["request_id"] = request_id
    business_result["response_id"] = response_id

    return business_result

# Register the endpoint with the router
router.post(
    "/example-endpoint",
    response_model=ExampleSuccessResponse,
    responses={
        400: {"model": ExampleErrorResponse, "description": "Bad Request"},
        401: {"model": ExampleErrorResponse, "description": "Unauthorized"},
        403: {"model": ExampleErrorResponse, "description": "Forbidden"},
        429: {"model": ExampleErrorResponse, "description": "Rate limit exceeded"},
        500: {"model": ExampleErrorResponse, "description": "Internal Server Error"},
    },
)(generic_post_endpoint)
