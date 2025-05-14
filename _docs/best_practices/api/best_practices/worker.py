"""
Production-ready, config-driven API worker utility for FastAPI endpoints.
Allows you to wrap any endpoint function with best practices for security, rate limiting, idempotency, tracing, logging, and credits enforcement.
Inspired by your deprecated I/O worker pattern, but designed for API endpoints.
"""
from fastapi import Request, HTTPException
from app.core.db_utils.security.log_sanitization import get_secure_logger
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.best_practices.utils.worker_utils import (
    get_tracing_ids,
    enforce_security,
    enforce_rate_limit,
    enforce_idempotency,
    apply_encryption,
    apply_decryption,
    enforce_credits,
)
import uuid, json
from functools import wraps
from fastapi import APIRouter, Depends, Request
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.best_practices.worker import api_worker
from app.core.valkey_core.client import ValkeyClient, get_valkey_client
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope, roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.security.mfa import get_mfa_service, MFAService
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.db_utils.security.log_sanitization import log_endpoint_event
from app.core.pulsar.decorators import pulsar_task

from pydantic import BaseModel
from typing import Any, Dict

class ExamplePayload(BaseModel):
    resource_id: str

class ExampleSuccessResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, Any]

class ExampleErrorResponse(BaseModel):
    detail: str

# --- Main Worker Decorator ---
def api_worker(config: JobConfig):
    """
    Decorator to wrap a FastAPI endpoint with production best practices.
    Usage:
        @api_worker(config)
        async def endpoint(...):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request: Request = kwargs.get("request")
            payload = kwargs.get("payload")
            verified = kwargs.get("verified")
            user = kwargs.get("user")
            roles = kwargs.get("roles")
            ip_ok = kwargs.get("ip_ok")
            mfa_service = kwargs.get("mfa_service")
            valkey_client = kwargs.get("valkey_client")
            logger = get_secure_logger(func.__module__)

            # --- Tracing IDs (from utility) ---
            tracing_ids = get_tracing_ids(request)
            request_id = tracing_ids["request_id"]
            response_id = tracing_ids["response_id"]

            # --- Security enforcement (from utility) ---
            await enforce_security(
                verified=verified,
                user=user,
                roles=roles,
                ip_ok=ip_ok,
                mfa_service=mfa_service,
            )

            # --- Rate limiting (from utility) ---
            await enforce_rate_limit(
                payload=payload,
                request=request,
                verified=verified,
                tracing_ids=tracing_ids,
            )

            # --- Idempotency enforcement (from utility) ---
            idempotency_result = await enforce_idempotency(
                request=request,
                valkey_client=valkey_client,
                tracing_ids=tracing_ids,
            )
            if idempotency_result:
                return idempotency_result

            # --- Decrypt incoming data (if enabled) ---
            decrypted_payload = payload.dict() if hasattr(payload, 'dict') else payload
            if hasattr(JobConfig, 'encryption') and getattr(JobConfig.encryption, 'enable_decryption', False):
                try:
                    decrypted_payload = apply_decryption(decrypted_payload)
                except Exception as e:
                    logger.error("Decryption failed", error=str(e), request_id=request_id, response_id=response_id)
                    raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

            # --- Caching (check before business logic) ---
            cache_key = f"{config.endpoint_name}:{verified['user'].id if verified and 'user' in verified else None}:{decrypted_payload.get('resource_id', '')}"
            cache_ttl = getattr(getattr(config, 'cache', object()), 'default_ttl', 60)
            cached_result = None
            if hasattr(config, 'cache') and getattr(config.cache, 'enabled', False):
                try:
                    from app.core.db_utils._docs.best_practices.api.best_practices.utils.worker_utils import enforce_cache
                    cached_result = await enforce_cache(
                        key=cache_key,
                        expensive_operation=lambda: None,  # Only check, don't compute
                        ttl=cache_ttl,
                        cache_backend=valkey_client,
                    )
                except Exception as e:
                    logger.error("Cache check failed", error=str(e), request_id=request_id, response_id=response_id)
            if cached_result:
                return cached_result

            # --- Business logic (call endpoint) ---
            try:
                # Pass decrypted payload as 'payload' kwarg
                kwargs["payload"] = decrypted_payload
                result = await func(*args, **kwargs)
            except Exception as exc:
                logger.error("Endpoint logic failed", error=str(exc), request_id=request_id, response_id=response_id)
                raise

            # --- Credits enforcement (on success only) ---
            try:
                if result and getattr(result, 'success', False):
                    if verified:
                        enforce_credits(
                            func=lambda: result,
                            request=request,
                            credit_type=config.credit_type,
                            db=db,
                            current_user=verified['user'],
                            credit_amount=config.required_credits,
                        )
            except Exception as exc:
                logger.error("Credits deduction failed", error=str(exc), request_id=request_id, response_id=response_id)

            # --- Encrypt outgoing data (if enabled) ---
            response_data = result.data if hasattr(result, 'data') else result
            if hasattr(JobConfig, 'encryption') and getattr(JobConfig.encryption, 'enable_encryption', False):
                try:
                    response_data = apply_encryption(response_data)
                except Exception as e:
                    logger.error("Encryption failed", error=str(e), request_id=request_id, response_id=response_id)
                    raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")
            # --- Set cache after business logic (if enabled) ---
            if hasattr(config, 'cache') and getattr(config.cache, 'enabled', False):
                try:
                    from app.core.db_utils._docs.best_practices.api.best_practices.utils.worker_utils import enforce_cache
                    await enforce_cache(
                        key=cache_key,
                        expensive_operation=lambda: response_data,
                        ttl=cache_ttl,
                        cache_backend=valkey_client,
                    )
                except Exception as e:
                    logger.error("Cache set failed", error=str(e), request_id=request_id, response_id=response_id)
            # --- Return response ---
            # Always return the correct response type, with encrypted data if required.
            if hasattr(result, 'dict'):
                return result.__class__(**{**result.dict(), "data": response_data})
            return result
        return wrapper
    return decorator



router = APIRouter()

@measure_performance(threshold_ms=100.0, level="warn", record_metric=True)
@trace_function(
    name=JobConfig.tracing.function_name,
    attributes={"route": JobConfig.endpoint_name},
    record_metrics=True,
    capture_exceptions=True,
)
@track_errors
@log_endpoint_event(JobConfig.tracing.function_name)
@pulsar_task(
    topic=JobConfig.pulsar_labeling.job_topic,
    producer_label=JobConfig.pulsar_labeling.producer_label,
    event_label=JobConfig.pulsar_labeling.event_label,
    max_retries=JobConfig.pulsar_labeling.max_retries,
    retry_delay=JobConfig.pulsar_labeling.retry_delay,
)
@api_worker(JobConfig())
async def generic_post_endpoint(
    payload: ExamplePayload,
    request: Request,
    valkey_client: ValkeyClient = Depends(get_valkey_client),
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: MFAService = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
) -> ExampleSuccessResponse:
    # Your business logic only!
    # All security, rate limiting, idempotency, credits, tracing/logging is handled by the worker/utilities.
    return {
        "success": True,
        "message": "Operation completed",
        "data": {"resource_id": payload.resource_id}
    }

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