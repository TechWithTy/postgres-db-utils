"""
worker_utils.py

Best-practice utility functions for use in I/O, DB, and CPU worker pools.
Implements standardized decorator composition, async patterns, and observability for each workload type.

Follows DRY, SOLID, and CI/CD best practices as outlined in project documentation.
"""

import functools
import logging
from typing import Any, Awaitable, Callable, Literal, Optional

from celery.result import AsyncResult
from fastapi import Depends
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from app.models.credit import CreditType
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
from app.core.db_utils.exceptions.exceptions import (
    APIError,
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    InsufficientCreditsError,
    ServiceTimeoutError,
    log_and_raise_http_exception,
)

# Set up logger
logger = logging.getLogger("app.core.db_utils.workers")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key")


def get_auth_dependency(
    auth_type: Literal["jwt", "api_key", "oauth", "mfa", "none"] | None = "jwt",
):
    if auth_type == "jwt":
        return Depends(oauth2_scheme)
    elif auth_type == "api_key":
        return Depends(api_key_scheme)
    elif auth_type == "oauth":
        return Depends(oauth2_scheme)
    elif auth_type == "mfa":
        return Depends(
            oauth2_scheme
        )  # MFA uses same scheme but with additional verification
    elif auth_type is None or auth_type == "none" or auth_type == "":
        return None
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
from app.core.db_utils.workers._schemas import IOTaskConfig


def run_io_task_with_best_practices(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: IOTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async I/O task as a Celery task with all best practices.
    Accepts a single config argument of type IOTaskConfig.
    Raises:
        InsufficientCreditsError, RateLimitError, ForbiddenError, ServiceTimeoutError, APIError
    """
    # Extract config values
    credit_type = config.credit_type
    credit_amount = config.credit_amount or 0
    auth_type = config.auth_type or "jwt"
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    max_retries = config.max_retries
    backoff = config.backoff
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    decorated_func = retry_decorator(max_retries=max_retries, backoff=backoff)(
        decorated_func
    )
    decorated_func = with_pool_metrics(decorated_func)
    # Optionally add circuit breaker if desired
    # decorated_func = circuit_breaker_decorator(max_attempts=3)(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if rate_limit is not None and rate_window is not None:
        decorated_func = rate_limit_decorator(
            limit=rate_limit, window=rate_window, endpoint=endpoint
        )(decorated_func)
    celery_wrapped = celery_task(queue="io", soft_time_limit=task_timeout)(
        decorated_func
    )

    def submit(*args, **kwargs) -> AsyncResult:
        try:
            auth_dep = get_auth_dependency(auth_type)
            req = kwargs.get("request")
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount}, endpoint={endpoint}, priority={task_priority}"
                )
                try:
                    return call_function_with_credits(
                        lambda request, user: celery_wrapped.apply_async(
                            args=args, kwargs=kwargs, priority=task_priority
                        ),
                        req,
                        credit_type,
                        credit_amount=credit_amount,
                    )
                except InsufficientCreditsError as ice:
                    log_and_raise_http_exception(
                        logger, InsufficientCreditsError, 0, credit_amount
                    )
            logger.info(
                f"Submitting Celery I/O task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}"
            )
            return celery_wrapped.apply_async(
                args=args, kwargs=kwargs, priority=task_priority
            )
        except RateLimitError as rle:
            log_and_raise_http_exception(logger, RateLimitError, 60)
        except ForbiddenError as fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as ste:
            log_and_raise_http_exception(
                logger, ServiceTimeoutError, endpoint, task_timeout
            )
        except Exception as e:
            logger.exception(f"Error in run_io_task_with_best_practices.submit: {e}")
            raise APIError(
                status_code=500,
                error_code="internal_error",
                message="An unexpected error occurred.",
                details={"exception": str(e)},
            )

    return submit


# --- DB Worker Utility ---
from app.core.db_utils.workers._schemas import DBTaskConfig


def run_db_task_with_best_practices(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: DBTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async DB task as a Celery task with all best practices.
    Accepts a single config argument of type DBTaskConfig.
    Raises:
        InsufficientCreditsError, RateLimitError, ForbiddenError, ServiceTimeoutError, APIError
    """
    credit_type = config.credit_type
    credit_amount = config.credit_amount or 0
    auth_type = config.auth_type or "jwt"
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    max_retries = config.max_retries
    backoff = config.backoff
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=250)(decorated_func)
    decorated_func = with_engine_connection(decorated_func)
    decorated_func = with_query_optimization(decorated_func)
    decorated_func = retry_decorator(max_retries=max_retries, backoff=backoff)(
        decorated_func
    )
    decorated_func = with_pool_metrics(decorated_func)
    decorated_func = with_encrypted_parameters(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if rate_limit is not None and rate_window is not None:
        decorated_func = rate_limit_decorator(
            limit=rate_limit, window=rate_window, endpoint=endpoint
        )(decorated_func)
    celery_wrapped = celery_task(queue="db", soft_time_limit=task_timeout)(
        decorated_func
    )

    def submit(*args, **kwargs) -> AsyncResult:
        try:
            auth_dep = get_auth_dependency(auth_type)
            req = kwargs.get("request")
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount}, endpoint={endpoint}, priority={task_priority}"
                )
                try:
                    return call_function_with_credits(
                        lambda request, user: celery_wrapped.apply_async(
                            args=args, kwargs=kwargs, priority=task_priority
                        ),
                        req,
                        credit_type,
                        credit_amount=credit_amount,
                    )
                except InsufficientCreditsError as ice:
                    log_and_raise_http_exception(
                        logger, InsufficientCreditsError, 0, credit_amount
                    )
            logger.info(
                f"Submitting Celery DB task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}"
            )
            return celery_wrapped.apply_async(
                args=args, kwargs=kwargs, priority=task_priority
            )
        except RateLimitError as rle:
            log_and_raise_http_exception(logger, RateLimitError, 60)
        except ForbiddenError as fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as ste:
            log_and_raise_http_exception(
                logger, ServiceTimeoutError, endpoint, task_timeout
            )
        except Exception as e:
            logger.exception(f"Error in run_db_task_with_best_practices.submit: {e}")
            raise APIError(
                status_code=500,
                error_code="internal_error",
                message="An unexpected error occurred.",
                details={"exception": str(e)},
            )

    return submit


# --- CPU Worker Utility ---
from app.core.db_utils.workers._schemas import CPUTaskConfig


def run_cpu_task_with_best_practices(
    task_func: Callable[..., Any],
    *,
    config: CPUTaskConfig,
) -> Callable[..., Any]:
    """
    Register a CPU-bound task as a Celery task with all best practices.
    Accepts a single config argument of type CPUTaskConfig.
    Raises:
        InsufficientCreditsError, RateLimitError, ForbiddenError, ServiceTimeoutError, APIError
    """
    credit_type = config.credit_type
    credit_amount = config.credit_amount or 1
    auth_type = config.auth_type or "jwt"
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    auto_estimate_credits = config.auto_estimate_credits
    max_retries = config.max_retries
    backoff = config.backoff
    cb_threshold = config.cb_threshold
    cb_timeout = config.cb_timeout
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=500)(decorated_func)
    decorated_func = retry_decorator(max_retries=max_retries, backoff=backoff)(
        decorated_func
    )
    decorated_func = with_pool_metrics(decorated_func)
    decorated_func = circuit_breaker_decorator(
        max_attempts=cb_threshold, timeout=cb_timeout
    )(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if rate_limit is not None and rate_window is not None:
        decorated_func = rate_limit_decorator(
            limit=rate_limit, window=rate_window, endpoint=endpoint
        )(decorated_func)
    celery_wrapped = celery_task(queue="cpu", soft_time_limit=task_timeout)(
        decorated_func
    )

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
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}, endpoint={endpoint}, priority={task_priority}"
                )
                try:
                    return call_function_with_credits(
                        lambda request, user: celery_wrapped.apply_async(
                            args=args, kwargs=kwargs, priority=task_priority
                        ),
                        req,
                        credit_type,
                        credit_amount=credit_amount_local,
                    )
                except InsufficientCreditsError as ice:
                    log_and_raise_http_exception(
                        logger, InsufficientCreditsError, 0, credit_amount_local
                    )
            logger.info(
                f"Submitting Celery CPU task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}"
            )
            return celery_wrapped.apply_async(
                args=args, kwargs=kwargs, priority=task_priority
            )
        except RateLimitError as rle:
            log_and_raise_http_exception(logger, RateLimitError, 60)
        except ForbiddenError as fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as ste:
            log_and_raise_http_exception(
                logger, ServiceTimeoutError, endpoint, task_timeout
            )
        except Exception as e:
            logger.exception(f"Error in run_cpu_task_with_best_practices.submit: {e}")
            raise APIError(
                status_code=500,
                error_code="internal_error",
                message="An unexpected error occurred.",
                details={"exception": str(e)},
            )

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


#! To do add permission roles context addition
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
