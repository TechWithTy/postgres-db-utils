"""
Production-ready, config-driven API worker utility for FastAPI endpoints.
Allows you to wrap any endpoint function with best practices for security, rate limiting, idempotency, tracing, logging, and credits enforcement.
Inspired by your deprecated I/O worker pattern, but designed for API endpoints.
"""
from fastapi import Request, HTTPException
from app.core.db_utils.security.log_sanitization import get_secure_logger
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.best_practices.worker_utils import (
    get_tracing_ids,
    enforce_security,
    enforce_rate_limit,
    enforce_idempotency,
)
from app.core.db_utils.credits.credits import call_function_with_credits
import uuid, json
from functools import wraps

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

            # --- Credits enforcement (on success only, after business logic) ---
            # This must be called after the endpoint logic, so we wrap the call below
            try:
                result = await func(*args, **kwargs)
                if result and result.get("success"):
                    if verified:
                        call_function_with_credits(
                            user_id=verified['user'].id,
                            required_credits=config.required_credits,
                            endpoint=config.endpoint_name,
                        )
            except Exception as exc:
                logger.error("Credits deduction failed", error=str(exc), request_id=request_id, response_id=response_id)
                raise HTTPException(status_code=500, detail="Internal credits error")

            # --- Logging and tracing IDs in response ---
            logger.info("Endpoint logic executed", request_id=request_id, response_id=response_id)
            if isinstance(result, dict):
                result["request_id"] = request_id
                result["response_id"] = response_id
            return result
        return wrapper
    return decorator

from fastapi import APIRouter, Depends, Request
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.best_practices.worker import api_worker
from app.core.db_utils._docs.best_practices.api.best_practices.example_route import (
    ExamplePayload, ExampleSuccessResponse, ExampleErrorResponse
)
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