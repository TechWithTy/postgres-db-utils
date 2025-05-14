"""
FastAPI Example: Secure, Observable CPU-Intensive Endpoint with Policy Enforcement

- Demonstrates production-grade patterns for CPU-bound tasks
- Uses strict Pydantic models and dependency injection
- Applies full decorator stack (metrics, tracing, error tracking, event streaming)
- Shows how to safely run CPU-bound work in FastAPI (with commentary)
- Enforces per-endpoint security policies using JobConfig/AuthServiceJobConfig
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request
from typing import Callable, Any, Dict
from pydantic import BaseModel
import time

from concurrent.futures import ProcessPoolExecutor
from app.core.db_utils._docs.best_practices.api.pipelines.config.AuthServiceJobConfig import AuthServiceJobConfig
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
from app.core.db_utils._docs.best_practices.api.pipelines.utils.worker_utils import cpu_hash_task
from app.core.db_utils.security.log_sanitization import log_endpoint_event
from app.core.pulsar.decorators import pulsar_task
from app.core.db_utils._docs.best_practices.api.pipelines.utils.policies import POLICY_ENFORCEMENT_MAP

# --- FastAPI App and Config ---
app = FastAPI()
config = AuthServiceJobConfig()

@app.on_event("startup")
async def set_event_loop():
    # * Store the current event loop for run_in_executor usage
    import asyncio
    app.state.loop = asyncio.get_running_loop()

# --- Pydantic Models ---
class CPUBoundPayload(BaseModel):
    """
    Input payload for CPU-bound endpoint.
    Example:
        {
            "data": "hello world",
            "rounds": 100000
        }
    """
    data: str
    rounds: int = 100000

class CPUBoundResponse(BaseModel):
    """
    Response for CPU-bound endpoint.
    Example:
        {
            "success": true,
            "message": "CPU-bound work completed",
            "result": "...",
            "elapsed": 2.34
        }
    """
    success: bool
    message: str
    result: str
    elapsed: float



# --- Route: CPU-Intensive Endpoint ---
@app.post("/cpu_intensive", response_model=CPUBoundResponse)
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
async def cpu_intensive(
    payload: CPUBoundPayload,
    request: Request,
    valkey_client: ValkeyClient = Depends(get_valkey_client),
    verified=Depends(get_verified_user) if JobConfig.security.auth_type_required else None,
    user=Depends(require_scope(JobConfig.security.user_permissions_required)) if JobConfig.security.user_permissions_required else None,
    db=Depends(lambda: None) if JobConfig.security.db_enabled else None,
    roles=Depends(roles_required(JobConfig.security.permission_roles_required)) if JobConfig.security.permission_roles_required else None,
    ip_ok=Depends(verify_ip_whitelisted) if getattr(JobConfig.security, 'ip_whitelist_enabled', False) else None,
    mfa_service: MFAService = Depends(get_mfa_service) if getattr(JobConfig.security, 'mfa_required', False) else None,
) -> CPUBoundResponse:
    """
    Example production-ready CPU-bound endpoint.
    ! Best practice: Offload CPU work to a process pool to avoid blocking event loop.
    * All security/policy dependencies are enforced per JobConfig (roles, scopes, MFA, IP, etc).
    * Adjust JobConfig for different policies per endpoint.
    """
    start = time.perf_counter()
    try:
        with ProcessPoolExecutor(max_workers=1) as pool:
            result = await app.state.loop.run_in_executor(pool, cpu_hash_task, payload.data, payload.rounds)
        elapsed = time.perf_counter() - start
        return CPUBoundResponse(
            success=True,
            message="CPU-bound work completed",
            result=result,
            elapsed=elapsed
        )
    except Exception as exc:
        # ! Log and return a structured error
        import logging
        logging.exception("CPU-bound task failed")
        raise HTTPException(status_code=500, detail=f"CPU-bound task failed: {exc}")

# --- Commentary ---
# ! CPU-bound tasks should NOT be run directly in FastAPI coroutines.
# ! Use ProcessPoolExecutor or background task queue (like Celery) to avoid blocking async I/O.
# * For heavy workloads, prefer Celery with a separate worker pool.
# * Limit concurrency to avoid resource exhaustion (see max_workers).

@app.get("/health")
def health_check():
    """Simple health check endpoint for readiness probes."""
    return {"status": "ok"}
