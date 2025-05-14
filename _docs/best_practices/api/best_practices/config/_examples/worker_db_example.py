"""
FastAPI Example: DB-Optimized Endpoint with Unified API Worker

- Demonstrates production-grade, config-driven enforcement using the api_worker pattern
- Handles DB optimization, caching, and circuit breaking
- All security, rate limiting, idempotency, and logging handled by the worker
"""
from fastapi import APIRouter, Request, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.db_utils.db_optimizations import get_optimized_user_profile
from app.core.db_utils._docs.best_practices.api.best_practices.JobConfig import JobConfig
from app.core.db_utils._docs.best_practices.api.best_practices.worker import api_worker
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.pulsar.decorators import pulsar_task
from app.core.db_utils.security.log_sanitization import log_endpoint_event
router = APIRouter()

class UserRequest(BaseModel):
    user_id: int

class UserResponse(BaseModel):
    success: bool
    user: dict | None = None
    message: str

@router.get("/db_worker_endpoint", response_model=UserResponse)
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
@api_worker(JobConfig)
async def db_worker_endpoint(
    payload: UserRequest,
    request: Request,
    db: Session = Depends(),
    valkey_client=Depends(lambda: None),
    verified=Depends(lambda: None),
    user=Depends(lambda: None),
    db_enabled=Depends(lambda: None),
    roles=Depends(lambda: None),
    ip_ok=Depends(lambda: None),
    mfa_service=Depends(lambda: None),
    **kwargs
) -> UserResponse:
    user = await get_optimized_user_profile(db, payload.user_id)
    if user:
        return UserResponse(success=True, user=user, message="User found")
    return UserResponse(success=False, user=None, message="User not found")
