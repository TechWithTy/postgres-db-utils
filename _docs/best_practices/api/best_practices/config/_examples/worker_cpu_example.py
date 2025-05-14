"""
FastAPI Example: CPU-Intensive Endpoint with Unified API Worker

- Demonstrates production-grade, config-driven enforcement using the api_worker pattern
- Handles CPU-bound work safely with ProcessPoolExecutor
- All security, rate limiting, idempotency, and logging handled by the worker
"""
from fastapi import APIRouter, Request, Depends
from pydantic import BaseModel
from concurrent.futures import ProcessPoolExecutor
import time, hashlib
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

class CPUPayload(BaseModel):
    data: str
    rounds: int = 100000

class CPUResponse(BaseModel):
    success: bool
    result: str
    elapsed: float

# --- CPU-Intensive Utility ---
def cpu_hash_task(data: str, rounds: int) -> str:
    hashed = data.encode()
    for _ in range(rounds):
        hashed = hashlib.sha256(hashed).digest()
    return hashed.hex()

@router.post("/cpu_worker_endpoint", response_model=CPUResponse)
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
async def cpu_worker_endpoint(
    payload: CPUPayload,
    request: Request,
    valkey_client=Depends(lambda: None),
    verified=Depends(lambda: None),
    user=Depends(lambda: None),
    db=Depends(lambda: None),
    roles=Depends(lambda: None),
    ip_ok=Depends(lambda: None),
    mfa_service=Depends(lambda: None),
    **kwargs
) -> CPUResponse:
    start = time.perf_counter()
    with ProcessPoolExecutor(max_workers=1) as pool:
        result = await request.app.state.loop.run_in_executor(pool, cpu_hash_task, payload.data, payload.rounds)
    elapsed = time.perf_counter() - start
    return CPUResponse(success=True, result=result, elapsed=elapsed)
