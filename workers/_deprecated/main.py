import logging
from typing import Any, Awaitable, Callable

from celery.result import AsyncResult
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer

from app.api.utils.credits.credits import call_function_with_credits

from app.core.db_utils.decorators import (
    retry_decorator,
    with_encrypted_parameters,
    with_engine_connection,
    with_pool_metrics,
    with_query_optimization,
)
from app.core.db_utils.exceptions.exceptions import (
    APIError,
    ForbiddenError,
    InsufficientCreditsError,
    RateLimitError,
    ServiceTimeoutError,
    log_and_raise_http_exception,
)

# --- I/O Worker Utility ---
from app.core.db_utils.workers._schemas import DBTaskConfig, IOTaskConfig
from app.core.db_utils.workers.utils.index import (
    _build_user_auth_component,
    circuit_breaker_decorator,
)
from app.core.valkey_core.client import client as RedisClient
from app.core.valkey_core.cache.decorators import cache as cache_decorator
from app.core.valkey_core.limiting.rate_limit import service_rate_limit, verify_and_limit
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)

from .utils.index import estimate_credits_for_task, permission_role_guard

# Set up logger
logger = logging.getLogger("app.core.db_utils.workers")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key")


def run_io_task_with_best_practices(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: IOTaskConfig,
    **_kwargs,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async I/O task as a Celery task with all best practices.
    Accepts a single config argument of type IOTaskConfig.
    Raises:
        InsufficientCreditsError, RateLimitError, ForbiddenError, ServiceTimeoutError, APIError
    """
    # Extract config values
    credit_type = getattr(config, "credit_type", None)
    credit_amount = getattr(config, "credit_amount", 0) or 0
    cache_ttl = getattr(config, "cache_ttl", None)
    rate_limit = getattr(config, "rate_limit", None)
    rate_window = getattr(config, "rate_window", None)
    max_retries = getattr(config, "max_retries", None)
    backoff = getattr(config, "backoff", None)
    task_timeout = getattr(config, "task_timeout", None)
    endpoint = getattr(config, "endpoint", None)
    task_priority = getattr(config, "task_priority", None)
    permission_roles = getattr(config, "permission_roles", ["admin"])


    decorated_func = trace_function(f"{task_func.__module__}.{task_func.__name__}")(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    decorated_func = retry_decorator(max_retries=max_retries)(
        decorated_func
    )
    decorated_func = with_pool_metrics(decorated_func)
    # Optionally add circuit breaker if desired
    # decorated_func = circuit_breaker_decorator(max_attempts=3)(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(
            RedisClient(),
            ttl=cache_ttl
        )(decorated_func)

    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)

    celery_wrapped = celery_task(
        f"{task_func.__module__}.{task_func.__name__}",
        queue="io",
        soft_time_limit=task_timeout
    )(decorated_func)
    

    use_credits = bool(credit_type and credit_amount)

    async def submit(*args, **kwargs) -> AsyncResult:
        try:
            req = kwargs.get("request")
            auth_header = req.headers.get("Authorization") if req else None
            nonlocal credit_amount
            if credit_type and credit_amount and req is not None:
                credit_amount_local = estimate_credits_for_task(task_func, req)
            else:
                credit_amount_local = credit_amount
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}, endpoint={endpoint}, priority={task_priority}, auth_type={auth_header}, roles={permission_roles}"
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
                except InsufficientCreditsError as _ice:
                    log_and_raise_http_exception(
                        logger, InsufficientCreditsError, 0, credit_amount_local
                    )
            logger.info(
                f"Submitting Celery I/O task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}, auth_type={auth_header}, roles={permission_roles}"
            )
            if rate_limit is not None and rate_window is not None:
                await verify_and_limit(
                    service_rate_limit(
                        limit=rate_limit, window=rate_window, endpoint=endpoint
                    )
                )
            return celery_wrapped.apply_async(
                args=args, kwargs=kwargs, priority=task_priority
            )
        except RateLimitError as _rle:
            log_and_raise_http_exception(logger, RateLimitError, 60)
        except ForbiddenError as _fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as _ste:
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
    credit_type = getattr(config, "credit_type", None)
    credit_amount = getattr(config, "credit_amount", 0) or 0
    cache_ttl = getattr(config, "cache_ttl", 300)
    rate_limit = getattr(config, "rate_limit", 100)
    rate_window = getattr(config, "rate_window", 60)
    max_retries = getattr(config, "max_retries", 3)
    backoff = getattr(config, "backoff", 2)
    task_timeout = getattr(config, "task_timeout", 60)
    endpoint = getattr(config, "endpoint", "db-task") 
    task_priority = getattr(config, "task_priority", 5)
    permission_roles = getattr(config, "permission_roles", ["admin"])


    decorated_func = trace_function(f"{task_func.__module__}.{task_func.__name__}")(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=250)(decorated_func)
    decorated_func = with_engine_connection(decorated_func)
    decorated_func = with_query_optimization(decorated_func)
    decorated_func = retry_decorator(max_retries=max_retries)(
        decorated_func
    )
    decorated_func = with_pool_metrics(decorated_func)
    decorated_func = with_encrypted_parameters(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(
            RedisClient(),
            ttl=cache_ttl
        )(decorated_func)
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)

    celery_wrapped = celery_task(
        f"{task_func.__module__}.{task_func.__name__}",
        queue="db",
        soft_time_limit=task_timeout
    )(decorated_func)
    

    use_credits = bool(credit_type and credit_amount)

    async def submit(*args, **kwargs) -> AsyncResult:
        try:
            req = kwargs.get("request")
            auth_header = req.headers.get("Authorization") if req else None
            nonlocal credit_amount
            if credit_type and credit_amount and req is not None:
                credit_amount_local = estimate_credits_for_task(task_func, req)
            else:
                credit_amount_local = credit_amount
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}, endpoint={endpoint}, priority={task_priority}, auth_type={auth_header}, roles={permission_roles}"
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
                except InsufficientCreditsError as _ice:
                    log_and_raise_http_exception(
                        logger, InsufficientCreditsError, 0, credit_amount_local
                    )
            logger.info(
                f"Submitting Celery DB task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}, auth_type={auth_header}, roles={permission_roles}"
            )
            if rate_limit is not None and rate_window is not None:
                await verify_and_limit(
                    service_rate_limit(
                        limit=rate_limit, window=rate_window, endpoint=endpoint
                    )
                )
            return celery_wrapped.apply_async(
                args=args, kwargs=kwargs, priority=task_priority
            )
        except RateLimitError as _rle:
            log_and_raise_http_exception(logger, RateLimitError, 60)
        except ForbiddenError as _fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as _ste:
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
from app.core.db_utils.workers._schemas import CPUTaskConfig  # noqa: E402


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
    credit_type = getattr(config, "credit_type", None)
    credit_amount = getattr(config, "credit_amount", 0) or 1
    cache_ttl = getattr(config, "cache_ttl", None)
    rate_limit = getattr(config, "rate_limit", None)
    rate_window = getattr(config, "rate_window", None)
    auto_estimate_credits = getattr(config, "auto_estimate_credits", False)
    max_retries = getattr(config, "max_retries", 3)
    backoff = getattr(config, "backoff", 2)
    cb_threshold = getattr(config, "cb_threshold", 10)
    cb_timeout = getattr(config, "cb_timeout", 60)
    task_timeout = getattr(config, "task_timeout", 60)
    endpoint = getattr(config, "endpoint", "cpu-task")
    task_priority = getattr(config, "task_priority", 5)
    permission_roles = getattr(config, "permission_roles", ["admin"])


    decorated_func = trace_function(f"{task_func.__module__}.{task_func.__name__}")(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=500)(decorated_func)
    decorated_func = retry_decorator(max_retries=max_retries)(
        decorated_func
    )
    decorated_func = with_pool_metrics(decorated_func)
    decorated_func = circuit_breaker_decorator(
        max_attempts=cb_threshold,
        wait_base=backoff,
        wait_max=cb_timeout
    )(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(
            RedisClient(),
            ttl=cache_ttl
        )(decorated_func)
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)

    celery_wrapped = celery_task(
        f"{task_func.__module__}.{task_func.__name__}",
        queue="cpu",
        soft_time_limit=task_timeout
    )(decorated_func)
    
    use_credits = bool(credit_type and credit_amount)

    async def submit(*args, **kwargs) -> AsyncResult:
        try:
            req = kwargs.get("request")
            auth_header = req.headers.get("Authorization") if req else None
            nonlocal credit_amount
            if (
                credit_type
                and credit_amount
                and auto_estimate_credits
                and req is not None
            ):
                credit_amount_local = estimate_credits_for_task(task_func, req)
            else:
                credit_amount_local = credit_amount
            if use_credits:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}, endpoint={endpoint}, priority={task_priority}, auth_type={auth_header}, roles={permission_roles}"
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
                f"Submitting Celery CPU task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}, auth_type={auth_header}, roles={permission_roles}"
            )
            if rate_limit is not None and rate_window is not None:
                await verify_and_limit(
                    service_rate_limit(
                        limit=rate_limit, window=rate_window, endpoint=endpoint
                    )
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
