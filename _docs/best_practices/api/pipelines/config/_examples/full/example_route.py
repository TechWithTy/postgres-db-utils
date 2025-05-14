"""
Production-ready, config-driven FastAPI endpoint example.
Order and comments follow best practices for async IO endpoints, security, and observability.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Any
import uuid
import json
from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.pipelines.utils.worker_utils import (
    enforce_security,
    enforce_rate_limit,
    enforce_idempotency,
    get_tracing_ids,
    enforce_cache,
    enforce_credits,
    apply_encryption,
    apply_decryption,
)
from app.core.valkey_core.client import ValkeyClient
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.pulsar.decorators import pulsar_task
from app.core.db_utils.security.log_sanitization import log_endpoint_event
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope
from app.core.db_utils.security.oauth_scope import roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted

from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig 

from app.core.db_utils.security.mfa import get_mfa_service, MFAService
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from typing import Any
import json
from app.core.pulsar.decorators import pulsar_task
from app.core.db_utils.security.log_sanitization import log_endpoint_event
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
    """
    Config-driven, production-ready POST endpoint pattern using DRY utilities.
    """
    # --- 1. Security enforcement (production utility) ---
    await enforce_security(
        verified=verified,
        user=user,
        roles=roles,
        ip_ok=ip_ok,
        mfa_service=mfa_service,
    )

    # --- 2. Rate limiting enforcement (production utility) ---
    await enforce_rate_limit(
        payload=payload,
        request=request,
        verified=verified,
        tracing_ids=await get_tracing_ids(request),
    )

    # --- 3. Idempotency enforcement (production utility) ---
    await enforce_idempotency(
        request=request,
        valkey_client=valkey_client,
        tracing_ids=await get_tracing_ids(request),
    )

    # --- 4. Caching (return early if hit, config-driven) ---
    # Compose cache key and TTL using config and resource/user context
    resource_id = payload.resource_id
    user_id = verified['user'].id if verified and isinstance(verified, dict) and 'user' in verified else None
    # Use DRY enforce_cache utility
    def expensive_operation():
        # ...simulate DB or business logic
        return {"result": "expensive result", "success": True}
    cached_result = await enforce_cache(
        key=f"{JobConfig.endpoint_name}:{user_id}:{resource_id}",
        expensive_operation=expensive_operation,
        ttl=JobConfig.cache.default_ttl,
        cache_backend=valkey_client,
    )
    if cached_result:
        return ExampleSuccessResponse(success=True, message="Cached result", data=cached_result)

    # --- 5. Main business logic placeholder ---
    business_result = {"success": True, "message": "Operation completed", "data": {"resource_id": resource_id}}

    # --- 6. Credits enforcement (only on success) ---
    if business_result.get("success"):
        await enforce_credits(
            func=None,  # Not used in this context
            request=request,
            credit_type=JobConfig.credits.credit_type,
            db=db,
            current_user=user,
            credit_amount=JobConfig.credits.required_credits,
        )

    # --- 7. Decrypt incoming data before business logic (if enabled) ---
    decrypted_payload = payload.dict()
    if JobConfig.encryption.enable_decryption:
        try:
            decrypted_payload = apply_decryption(decrypted_payload)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    # Validate decrypted data (optional: add Pydantic validation here)
    # Example: Only allow whitelisted fields to be processed/returned
    allowed_fields = ("resource_id", "other_data")
    safe_fields = {k: v for k, v in decrypted_payload.items() if k in allowed_fields}

    # --- 8. Merge business and decrypted data, then encrypt response (if enabled) ---
    updated_data = {**business_result["data"], **safe_fields}
    response_data = updated_data
    if JobConfig.encryption.enable_encryption:
        try:
            response_data = apply_encryption(updated_data)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

    # --- 9. Return response ---
    return ExampleSuccessResponse(
        success=True,
        message="Request processed successfully",
        data=response_data
    )

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
