"""
FastAPI Example: DB-Optimized Endpoint with Unified API Worker

- Demonstrates production-grade, config-driven enforcement using the api_worker pattern
- Handles DB optimization, caching, and circuit breaking
- All security, rate limiting, idempotency, and logging handled by the worker
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Any
import logging

# Example: global/mock backends (replace with real DI in prod)
global_cache_backend = None  # e.g., ValkeyClient()
global_rate_limit_backend = None
global_circuit_breaker_backend = None
global_tracing_backend = None
global_metrics_backend = None
global_security_backend = None
global_encryption_backend = None

from app.core.db_utils._docs.best_practices.api.pipelines.utils.policies import POLICY_ENFORCEMENT_MAP

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

from app.core.db_utils.db_optimizations import (
    QUERY_COUNT, QUERY_DURATION, cache_result, 
    QueryOptimizer, OptimizedQuerySetMixin, get_optimized_user_profile
)
from app.core.db_utils.pool import get_db_session
from app.core.valkey_core.client import ValkeyClient, get_valkey_client
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.db_utils.security.log_sanitization import log_endpoint_event
from app.core.pulsar.decorators import pulsar_task
from app.core.db_utils._docs.best_practices.api.pipelines.JobConfig import JobConfig
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope, roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.security.mfa import get_mfa_service
from app.core.db_utils._docs.best_practices.api.pipelines.utils.policies import enforce_all_policies

from circuitbreaker import CircuitBreakerError



config = JobConfig()
router = APIRouter()
db_worker_policy = enforce_all_policies("db_worker_endpoint", config)
optimized_queryset_policy = enforce_all_policies("optimized_queryset", config)
logger = logging.getLogger(__name__)

class UserInDB(BaseModel):
    id: int
    name: str
    email: str
class UserResponse(BaseModel):
    success: bool
    user: UserInDB | None = None
    message: str

# --- Example: OptimizedQuerySetMixin for dependency injection ---
class UserProfileQuerySet(OptimizedQuerySetMixin):
    """
    Example mixin for UserProfile queries with joinedload/selectinload optimizations.
    """
    from app.models import UserProfile  # type: ignore
    model = UserProfile
    join_related_fields = ["user"]
    select_related_fields = ["profile_settings"]

# --- Route: Optimized single-object query with Prometheus, circuit breaker, and cache ---
@router.post(
    "/db_worker_endpoint",
    response_model=UserInDB,
    dependencies=[db_worker_policy],
)
@measure_performance(threshold_ms=150.0, level="warn", record_metric=True)
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
@cache_result(ttl=60)
async def get_user_profile(
    user_id: int,
    payload: Any,
    request: Request,
    valkey_client: ValkeyClient = Depends(get_valkey_client),
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db: Session = Depends(get_db_session),
    db_enabled=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: Any = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
) -> UserInDB:
    timer = QUERY_DURATION.time()
    try:
        QUERY_COUNT.labels(status="started").inc()
        query = QueryOptimizer.optimize_single_object_query(
            model_class=UserProfileQuerySet.model,
            query_params={"id": user_id},
            join_related_fields=UserProfileQuerySet.join_related_fields,
            select_related_fields=UserProfileQuerySet.select_related_fields,
            db_session=db
        )
        result = query.first()
        if not result:
            QUERY_COUNT.labels(status="not_found").inc()
            raise HTTPException(status_code=404, detail="UserProfile not found")
        QUERY_COUNT.labels(status="success").inc()
        return UserInDB(id=result.id, name=result.name, email=result.email)
    except CircuitBreakerError:
        QUERY_COUNT.labels(status="circuit_breaker").inc()
        logger.error("DB circuit breaker triggered for user_id=%s", user_id)
        raise HTTPException(status_code=503, detail="Database temporarily unavailable")
    except Exception as exc:
        QUERY_COUNT.labels(status="error").inc()
        logger.exception("DB error: %s", exc)
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        timer.observe_duration()

# --- Route: Optimized queryset with joinedload/selectinload ---
@router.get("/user_profiles", response_model=list[UserInDB], dependencies=[optimized_queryset_policy])
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
async def list_user_profiles(
    payload: Any,
    request: Request,
    valkey_client: ValkeyClient = Depends(get_valkey_client),
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db: Session = Depends(get_db_session),
    db_enabled=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    qs: UserProfileQuerySet = Depends(UserProfileQuerySet),
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: Any = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
) -> list[UserInDB]:
    query = qs.get_query(db)
    results = query.limit(10).all()
    return [UserInDB(id=u.id, name=u.name, email=u.email) for u in results]

# --- Route: Using the get_optimized_user_profile helper ---
@router.get("/optimized_user_profile/{user_id}", response_model=UserInDB, dependencies=[db_worker_policy])
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
async def get_optimized_user_profile_route(
    user_id: int,
    payload: Any,
    request: Request,
    valkey_client: ValkeyClient = Depends(get_valkey_client),
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db: Session = Depends(get_db_session),
    db_enabled=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: Any = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
) -> UserInDB:
    query = get_optimized_user_profile(user_id=user_id, db_session=db)
    result = query.first()
    if not result:
        raise HTTPException(status_code=404, detail="UserProfile not found")
    return UserInDB(id=result.id, name=result.name, email=result.email)
