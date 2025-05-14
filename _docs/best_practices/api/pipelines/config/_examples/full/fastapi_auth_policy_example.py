"""
FastAPI Example: Secure Per-Endpoint Auth Policy using AuthServiceJobConfig

How it works with your current Auth model:
- Each route is mapped to an endpoint name (e.g., 'get_user_info')
- AuthServiceJobConfig.endpoint_auth defines the required policy (auth level, roles, scopes, MFA) for each endpoint
- AuthServiceJobConfig.default_endpoint_auth provides a secure fallback for any unlisted endpoint
- The enforcement dependency reads the policy for the current endpoint and checks the current user against it
- User info (roles, scopes, MFA, etc.) would be extracted from a JWT or session in production
- This pattern ensures that all endpoints are protected according to your config, with no accidental public routes

How to use:
- Adjust get_current_user to extract real user info from your JWT/session (see todo in code)
- Use make_secured_route('endpoint_name') in your route to enforce the correct policy
- Add or update endpoint policies in AuthServiceJobConfig as your API evolves

- Demonstrates usage of endpoint_auth and default_endpoint_auth
- Shows role/scope/MFA checks
- Production-ready enforcement pattern
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request
from typing import Callable
from app.core.db_utils._docs.best_practices.api.pipelines.config.AuthServiceJobConfig import (
    AuthServiceJobConfig
)
from fastapi import Request, Depends
from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig
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
from app.core.db_utils._docs.best_practices.api.pipelines.utils.policies import POLICY_ENFORCEMENT_MAP
from pydantic import BaseModel
from typing import Any, Dict

# --- FastAPI App and Routes ---
app = FastAPI()
config = AuthServiceJobConfig()  # In real app, inject/configure as needed

class ExamplePayload(BaseModel):
    resource_id: str

class ExampleSuccessResponse(BaseModel):
    success: bool
    message: str
    data: Dict[str, Any]
  

# Example: global/mock backends (replace with real DI in prod)
global_cache_backend = None  # e.g., ValkeyClient()
global_rate_limit_backend = None
global_circuit_breaker_backend = None
global_tracing_backend = None
global_metrics_backend = None
global_security_backend = None
global_encryption_backend = None

def enforce_all_policies(endpoint_name: str):
    async def dependency(request: Request):
        endpoint_cfg = config.endpoint_configs.get(endpoint_name, config.default_endpoint_config)
        for policy_name, policy_func in POLICY_ENFORCEMENT_MAP.items():
            policy_cfg = getattr(endpoint_cfg, policy_name, None)
            if policy_cfg and getattr(policy_cfg, "enabled", False):
                backend_arg = {
                    "cache_backend": global_cache_backend,
                    "rate_limit_backend": global_rate_limit_backend,
                    "circuit_breaker_backend": global_circuit_breaker_backend,
                    "tracing_backend": global_tracing_backend,
                    "metrics_backend": global_metrics_backend,
                    "security_backend": global_security_backend,
                    "encryption_backend": global_encryption_backend,
                }.get(f"{policy_name}_backend", None)
                await policy_func(
                    endpoint_name=endpoint_name,
                    config=config,
                    request=request,
                    **({f"{policy_name}_backend": backend_arg} if backend_arg else {})
                )
    return Depends(dependency)

@app.post("/sign_up")
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
async def sign_up(
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
    return {
        "success": True,
        "message": "Sign up is public",
        "data": {"resource_id": payload.resource_id}
    }

@app.post("/get_user_info")
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
async def get_user_info(
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
    return {
        "success": True,
        "message": "User info",
        "data": {"resource_id": payload.resource_id}
    }

@app.post("/admin_only")
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
async def admin_only(
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
    return {
        "success": True,
        "message": "Admin only",
        "data": {"resource_id": payload.resource_id}
    }

@app.post("/health")
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
async def health(
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
    return {
        "success": True,
        "message": "OK",
        "data": {"resource_id": payload.resource_id}
    }

@app.post("/unlisted")
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
async def unlisted(
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
    return {
        "success": True,
        "message": "This uses the default (secure) policy",
        "data": {"resource_id": payload.resource_id}
    }

@app.get("/has_admin_only_config")
def has_admin_only_config():
    """
    Checks if the AuthServiceJobConfig includes an 'admin_only' endpoint in endpoint_configs.
    Returns the config if present, otherwise returns False.
    """
    from app.core.db_utils._docs.best_practices.api.pipelines.config.AuthServiceJobConfig import AuthServiceJobConfig
    config = AuthServiceJobConfig()
    admin_only = config.endpoint_configs.get("admin_only")
    if admin_only:
        return {"admin_only_present": True, "admin_only_config": admin_only.model_dump()}
    return {"admin_only_present": False}
