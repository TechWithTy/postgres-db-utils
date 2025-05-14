"""
FastAPI Example: Auth Policy Endpoint with Unified API Worker

- Demonstrates config-driven, per-endpoint policy enforcement using the api_worker pattern
- All security, rate limiting, idempotency, and logging handled by the worker
- Shows how to adjust JobConfig for endpoint-specific policies
"""
from fastapi import APIRouter, Request
from pydantic import BaseModel
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

class AuthPayload(BaseModel):
    resource_id: str

class AuthResponse(BaseModel):
    success: bool
    message: str
    data: dict | None = None

@router.post("/auth_worker_endpoint", response_model=AuthResponse)
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
async def auth_worker_endpoint(
    payload: AuthPayload,
    request: Request,
    valkey_client=Depends(lambda: None),
    verified=Depends(lambda: None),
    user=Depends(lambda: None),
    db=Depends(lambda: None),
    roles=Depends(lambda: None),
    ip_ok=Depends(lambda: None),
    mfa_service=Depends(lambda: None),
    **kwargs
) -> AuthResponse:
    # Example: enforce additional policy logic if needed
    return AuthResponse(success=True, message="Authorized", data={"resource_id": payload.resource_id})
