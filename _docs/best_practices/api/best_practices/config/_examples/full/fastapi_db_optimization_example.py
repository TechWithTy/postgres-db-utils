"""
Example: Production-Ready FastAPI Route with Optimized DB Access

- Demonstrates integration of db_optimizations.py utilities
- Uses Prometheus metrics, circuit breaker, and Valkey cache
- Follows DRY, SOLID, and CI/CD best practices
- Strict type hints and Pydantic models
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Any, Callable, Dict
import logging

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
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.best_practices.config.AuthServiceJobConfig import (
    AuthServiceJobConfig
)
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.security.oauth_scope import require_scope, roles_required
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
from app.core.db_utils.security.mfa import get_mfa_service, MFAService
from app.core.db_utils._docs.best_practices.api.best_practices.utils.policies import POLICY_ENFORCEMENT_MAP
from circuitbreaker import CircuitBreakerError

router = APIRouter()
logger = logging.getLogger(__name__)

# ---
# All endpoints are instrumented for observability, tracing, error tracking, and event streaming.
# This stack ensures:
# - Prometheus metrics (performance, latency)
# - Distributed tracing with OpenTelemetry
# - Error tracking with Sentry or compatible backend
# - Structured endpoint event logging
# - Pulsar event streaming for async/offloaded processing
#
# Use this pattern for every production endpoint!
# ---

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
@router.get("/user_profile/{user_id}", response_model=UserInDB)
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
    """
    Demonstrates optimize_single_object_query, Prometheus metrics, and circuit breaker.
    """
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
@router.get("/user_profiles", response_model=list[UserInDB])
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
    """
    Demonstrates optimize_queryset with retry logic and relationship loading.
    """
    query = qs.get_query(db)
    results = query.limit(10).all()
    return [UserInDB(id=u.id, name=u.name, email=u.email) for u in results]

# --- Route: Using the get_optimized_user_profile helper ---
@router.get("/optimized_user_profile/{user_id}", response_model=UserInDB)
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
    """
    Demonstrates use of get_optimized_user_profile utility.
    """
    query = get_optimized_user_profile(user_id=user_id, db_session=db)
    result = query.first()
    if not result:
        raise HTTPException(status_code=404, detail="UserProfile not found")