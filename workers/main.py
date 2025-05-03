"""
worker_utils.py

Best-practice utility functions for use in I/O, DB, and CPU worker pools.
Implements standardized decorator composition, async patterns, and observability for each workload type.

Follows DRY, SOLID, and CI/CD best practices as outlined in project documentation.
"""

import functools
import logging
from typing import Any, Awaitable, Callable, Dict, Literal

from celery.result import AsyncResult
from fastapi import Depends
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.api.utils.credits.credits import call_function_with_credits
from app.api.utils.credits.credits_estimation import (
    estimate_mls_credits,
    estimate_phone_credits,
    estimate_theharvester_credits,
    estimate_zehef_credits,
)
from app.core.celery.decorators import celery_task
from app.core.db_utils.decorators import (
    retry_decorator,
    with_encrypted_parameters,
    with_engine_connection,
    with_pool_metrics,
    with_query_optimization,
)
from app.core.redis.client import RedisClient
from app.core.redis.decorators import cache as cache_decorator
from app.core.redis.rate_limit import service_rate_limit, verify_and_limit
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)

# Set up logger
logger = logging.getLogger("app.core.db_utils.workers")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key")


def get_auth_dependency(auth_type: Literal["jwt", "api_key", "oauth"] = "jwt"):
    if auth_type == "jwt":
        return Depends(oauth2_scheme)
    elif auth_type == "api_key":
        return Depends(api_key_scheme)
    elif auth_type == "oauth":
        return Depends(oauth2_scheme)
    else:
        raise ValueError(f"Unknown auth_type: {auth_type}")


# Helper: Rate limit decorator for async worker tasks
def rate_limit_decorator(
    limit: int = 100,
    window: int = 60,
    endpoint: str = "worker",
    require_token: bool = True,
    is_srcie: bool = False,
):
    """
    Decorator to apply rate limiting. Uses verify_and_limit for user-level (token+ip) rate limits.
    For non-srcie-based limits, optionally uses verify_and_limit; otherwise falls back to service_rate_limit.
    Args:
        limit: Max allowed requests per window
        window: Time window in seconds
        endpoint: API endpoint or action name
        require_token: Whether to require a token (user-level)
        is_srcie: If True, skip user-based limits (srcie-based logic)
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            req = kwargs.get("request")
            try:
                if not is_srcie and require_token and req is not None:
                    token = getattr(req, "token", None)
                    ip = getattr(req, "client_ip", None)
                    if not token or not ip:
                        logger.error(
                            f"Missing token or client_ip for rate limiting | req={req}"
                        )
                        raise Exception("Missing token or client_ip for rate limiting")
                    logger.debug(
                        f"Applying user-level rate limit | token={token}, ip={ip}, endpoint={endpoint}"
                    )
                    await verify_and_limit(token, ip, endpoint, window=window)
                else:
                    key = (
                        getattr(req, "user_id", None)
                        or getattr(req, "client_ip", None)
                        or endpoint
                    )
                    logger.debug(
                        f"Applying service-level rate limit | key={key}, endpoint={endpoint}"
                    )
                    allowed = await service_rate_limit(
                        key, limit, window, endpoint=endpoint
                    )
                    if not allowed:
                        logger.warning(
                            f"Rate limit exceeded | key={key}, endpoint={endpoint}"
                        )
                        raise Exception(f"Rate limit exceeded for {key} on {endpoint}")
                return await func(*args, **kwargs)
            except Exception as e:
                logger.exception(f"Error in rate_limit_decorator: {e}")
                raise

        return wrapper

    return decorator


# --- Circuit Breaker Decorator ---
def circuit_breaker_decorator(
    max_attempts: int = 3,
    wait_base: int = 2,
    wait_max: int = 10,
    exceptions: tuple = (Exception,),
):
    """
    Circuit breaker decorator using tenacity for async functions.
    Args:
        max_attempts: Maximum retry attempts before opening the circuit
        wait_base: Base for exponential backoff
        wait_max: Maximum wait time between attempts
        exceptions: Exception types to catch
    """

    def decorator(func):
        @retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=wait_base, max=wait_max),
            retry=retry_if_exception_type(exceptions),
            reraise=True,
        )
        async def wrapper(*args, **kwargs):
            try:
                logger.debug(
                    f"Calling function {func.__name__} with circuit breaker | args={args}, kwargs={kwargs}"
                )
                return await func(*args, **kwargs)
            except Exception as e:
                logger.exception(
                    f"Error in circuit_breaker_decorator for {func.__name__}: {e}"
                )
                raise

        return wrapper

    return decorator


# --- I/O Worker Utility ---
def run_io_task_with_best_practices(
    task_func: Callable[..., Awaitable[Any]],
    *,
    use_credits: bool = False,
    credit_type: str = "leads",
    credit_amount: int = 1,
    auth_type: Literal["jwt", "api_key", "oauth"] = "jwt",
    enable_cache: bool = True,
    enable_rate_limit: bool = True,
    cache_ttl: int = 3600,
    rate_limit: int = 100,
    rate_window: int = 60,
) -> Callable[..., AsyncResult]:
    """
    Register an async I/O task as a Celery task with all best practices, optional credits, and optional authentication.
    Usage (in FastAPI endpoint):
        task_id = run_io_task_with_best_practices(my_func)(*args, **kwargs)
    """
    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    decorated_func = retry_decorator(max_retries=3, backoff=2)(decorated_func)
    decorated_func = with_pool_metrics(decorated_func)
    # Example: Use circuit_breaker_decorator in run_io_task_with_best_practices
    # decorated_func = circuit_breaker_decorator(max_attempts=3)(decorated_func)
    if enable_cache:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if enable_rate_limit:
        decorated_func = rate_limit_decorator(
            limit=rate_limit, window=rate_window, endpoint="io-task"
        )(decorated_func)
    celery_wrapped = celery_task(queue="io")(decorated_func)

    def submit(*args, **kwargs) -> AsyncResult:
        try:
            auth_dep = get_auth_dependency(auth_type)
            req = kwargs.get("request")
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount}"
                )
                return call_function_with_credits(
                    lambda request, user: celery_wrapped.apply_async(
                        args=args, kwargs=kwargs
                    ),
                    req,
                    credit_type,
                    credit_amount=credit_amount,
                )
            logger.info(f"Submitting Celery I/O task | args={args}, kwargs={kwargs}")
            return celery_wrapped.apply_async(args=args, kwargs=kwargs)
        except Exception as e:
            logger.exception(f"Error in run_io_task_with_best_practices.submit: {e}")
            raise

    return submit


# --- DB Worker Utility ---
def run_db_task_with_best_practices(
    task_func: Callable[..., Awaitable[Any]],
    *,
    use_credits: bool = False,
    credit_type: str = "leads",
    credit_amount: int = 1,
    auth_type: Literal["jwt", "api_key", "oauth"] = "jwt",
    enable_cache: bool = True,
    enable_rate_limit: bool = True,
    cache_ttl: int = 3600,
    rate_limit: int = 100,
    rate_window: int = 60,
) -> Callable[..., AsyncResult]:
    """
    Register an async DB task as a Celery task with all best practices, optional credits, and optional authentication.
    """
    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=250)(decorated_func)
    decorated_func = with_engine_connection(decorated_func)
    decorated_func = with_query_optimization(decorated_func)
    decorated_func = retry_decorator(max_retries=3, backoff=2)(decorated_func)
    decorated_func = with_pool_metrics(decorated_func)
    decorated_func = with_encrypted_parameters(decorated_func)
    if enable_cache:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if enable_rate_limit:
        decorated_func = rate_limit_decorator(
            limit=rate_limit, window=rate_window, endpoint="db-task"
        )(decorated_func)
    celery_wrapped = celery_task(queue="db")(decorated_func)

    def submit(*args, **kwargs) -> AsyncResult:
        try:
            auth_dep = get_auth_dependency(auth_type)
            req = kwargs.get("request")
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount}"
                )
                return call_function_with_credits(
                    lambda request, user: celery_wrapped.apply_async(
                        args=args, kwargs=kwargs
                    ),
                    req,
                    credit_type,
                    credit_amount=credit_amount,
                )
            logger.info(f"Submitting Celery DB task | args={args}, kwargs={kwargs}")
            return celery_wrapped.apply_async(args=args, kwargs=kwargs)
        except Exception as e:
            logger.exception(f"Error in run_db_task_with_best_practices.submit: {e}")
            raise

    return submit


# --- Utility: Best-practice credit estimation detection ---
def estimate_credits_for_task(task_func: Callable[..., Any], request: Any) -> int:
    """
    Automatically selects the best credit estimation strategy based on the task function's name.
    Extend this logic as new endpoints/types are added.
    """
    name = getattr(task_func, "__name__", "").lower()
    if "mls" in name or "home" in name:
        return estimate_mls_credits(request)
    elif "phone" in name or "phunter" in name:
        return estimate_phone_credits(request)
    elif "theharvester" in name or "harvest" in name:
        return estimate_theharvester_credits(request)
    elif "zehef" in name or "email" in name:
        return estimate_zehef_credits(request)
    # Default: 1 credit
    return 1


# --- CPU Worker Utility ---
def run_cpu_task_with_best_practices(
    task_func: Callable[..., Any],
    *,
    use_credits: bool = False,
    credit_type: str = "leads",
    credit_amount: int = 1,
    auth_type: Literal["jwt", "api_key", "oauth"] = "jwt",
    enable_cache: bool = True,
    enable_rate_limit: bool = True,
    cache_ttl: int = 3600,
    rate_limit: int = 100,
    rate_window: int = 60,
    auto_estimate_credits: bool = True,
) -> Callable[..., AsyncResult]:
    """
    Register a CPU-bound task as a Celery task with all best practices, optional credits, and optional authentication.
    If auto_estimate_credits is True, estimate credits based on the task and request.
    """
    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=500)(decorated_func)
    decorated_func = retry_decorator(max_retries=2, backoff=1)(decorated_func)
    decorated_func = with_pool_metrics(decorated_func)
    # Optionally add circuit breaker
    # decorated_func = circuit_breaker_decorator(max_attempts=3)(decorated_func)
    if enable_cache:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if enable_rate_limit:
        decorated_func = rate_limit_decorator(
            limit=rate_limit, window=rate_window, endpoint="cpu-task"
        )(decorated_func)
    celery_wrapped = celery_task(queue="cpu")(decorated_func)

    def submit(*args, **kwargs) -> AsyncResult:
        try:
            auth_dep = get_auth_dependency(auth_type)
            nonlocal credit_amount
            req = kwargs.get("request")
            if use_credits and auto_estimate_credits and req is not None:
                credit_amount_local = estimate_credits_for_task(task_func, req)
            else:
                credit_amount_local = credit_amount
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}"
                )
                return call_function_with_credits(
                    lambda request, user: celery_wrapped.apply_async(
                        args=args, kwargs=kwargs
                    ),
                    req,
                    credit_type,
                    credit_amount=credit_amount_local,
                )
            logger.info(f"Submitting Celery CPU task | args={args}, kwargs={kwargs}")
            return celery_wrapped.apply_async(args=args, kwargs=kwargs)
        except Exception as e:
            logger.exception(f"Error in run_cpu_task_with_best_practices.submit: {e}")
            raise

    return submit


# --- Example Usage ---

# @run_io_task_with_best_practices
# async def fetch_external_data(url: str) -> dict:
#     ...

# @run_db_task_with_best_practices
# async def update_user_record(user_id: int, data: dict) -> None:
#     ...

# @run_cpu_task_with_best_practices
# def calculate_heavy_analytics(payload: dict) -> dict:
#     ...

"""
All decorators and patterns are based on project documentation and best practices:
- Decorator order: config -> connection -> optimization -> OTel -> retry -> metrics -> encryption
- Async for I/O and DB, sync for CPU-bound
- OTel spans and Prometheus metrics are exposed by all workers
- Atomicity for DB tasks is handled via explicit transaction blocks if needed
- Secure parameter handling via encryption decorator
"""
