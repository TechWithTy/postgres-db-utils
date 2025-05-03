# --- Pulsar Worker Utilities (Celery-Independent, Best Practices) ---
import functools
import logging
from typing import Any, Awaitable, Callable, Literal, Optional

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
from app.core.db_utils.exceptions.exceptions import (
    APIError,
    ForbiddenError,
    InsufficientCreditsError,
    RateLimitError,
    ServiceTimeoutError,
    log_and_raise_http_exception,
)
from app.core.db_utils.workers._schemas import (
    PulsarCPUTaskConfig,
    PulsarDBTaskConfig,
    PulsarIOTaskConfig,
)
from app.core.pulsar.decorators import (
    pulsar_task,
    validate_topic_permissions,
)
from app.core.redis.client import RedisClient
from app.core.redis.decorators import cache as cache_decorator
from app.core.redis.rate_limit import service_rate_limit, verify_and_limit
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)

logger = logging.getLogger("app.core.db_utils.workers.pulsar")


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key")


def estimate_credits_for_task(task_func: Callable[..., Any], request: Any) -> int:
    name = getattr(task_func, "__name__", "").lower()
    if "mls" in name or "home" in name:
        return estimate_mls_credits(request)
    elif "phone" in name or "phunter" in name:
        return estimate_phone_credits(request)
    elif "theharvester" in name or "harvest" in name:
        return estimate_theharvester_credits(request)
    elif "zehef" in name or "email" in name:
        return estimate_zehef_credits(request)
    return 1


def get_auth_dependency(
    auth_type: str | None = "jwt",
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


# --- Rate Limiting Decorator for Pulsar Tasks ---
def rate_limit_decorator_pulsar(
    limit: int = 100,
    window: int = 60,
    endpoint: str = "worker",
    require_token: bool = True,
    is_srcie: bool = False,
):
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
                logger.exception(f"Error in rate_limit_decorator_pulsar: {e}")
                raise

        return wrapper

    return decorator


# --- Circuit Breaker Decorator for Pulsar Tasks ---
def circuit_breaker_decorator_pulsar(
    max_attempts: int = 3,
    wait_base: int = 2,
    wait_max: int = 10,
    exceptions: tuple = (Exception,),
):
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
                    f"Error in circuit_breaker_decorator_pulsar for {func.__name__}: {e}"
                )
                raise

        return wrapper

    return decorator


# --- Pulsar Task Registration Utilities ---
def run_io_task_with_best_practices_pulsar(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: PulsarIOTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async I/O task as a Pulsar publisher with all best practices, including caching, rate limiting, retries, circuit breaker, metrics, and permissions.
    Usage:
        await run_io_task_with_best_practices_pulsar(my_func, config=PulsarIOTaskConfig())(*args, **kwargs)
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
    topic = config.topic
    dlq_topic = config.dlq_topic
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    decorated_func = circuit_breaker_decorator_pulsar(
        max_attempts=max_retries, wait_base=backoff
    )(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if rate_limit is not None and rate_window is not None:
        decorated_func = rate_limit_decorator_pulsar(
            limit=rate_limit, window=rate_window, endpoint=endpoint
        )(decorated_func)
    if permission_roles:
        decorated_func = validate_topic_permissions(
            topic=topic, roles=permission_roles
        )(decorated_func)
    decorated_func = pulsar_task(
        topic=topic, dlq_topic=dlq_topic, priority=task_priority, timeout=task_timeout
    )(decorated_func)

    async def submit(*args, **kwargs) -> Any:
        try:
            req = kwargs.get("request")
            auth_dep = get_auth_dependency(auth_type)
            if credit_amount > 0:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount}, endpoint={endpoint}, priority={task_priority}"
                )
                return await call_function_with_credits(
                    lambda request, user: decorated_func(*args, **kwargs),
                    req,
                    credit_type,
                    credit_amount=credit_amount,
                )
            logger.info(
                f"Submitting Pulsar I/O task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}"
            )
            return await decorated_func(*args, **kwargs)
        except InsufficientCreditsError as ice:
            log_and_raise_http_exception(logger, InsufficientCreditsError)
        except RateLimitError as rle:
            log_and_raise_http_exception(logger, RateLimitError)
        except ForbiddenError as fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as ste:
            log_and_raise_http_exception(
                logger, ServiceTimeoutError, endpoint, task_timeout
            )
        except Exception as e:
            logger.exception(
                f"Error in run_io_task_with_best_practices_pulsar.submit: {e}"
            )
            raise APIError(
                status_code=500,
                error_code="internal_error",
                message="An unexpected error occurred.",
                details={"exception": str(e)},
            )

    return submit


def run_db_task_with_best_practices_pulsar(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: PulsarDBTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async DB task as a Pulsar publisher with all best practices, including caching, rate limiting, retries, circuit breaker, metrics, and permissions.
    Usage:
        await run_db_task_with_best_practices_pulsar(my_func, config=PulsarDBTaskConfig())(*args, **kwargs)
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
    topic = config.topic
    dlq_topic = config.dlq_topic
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=250)(decorated_func)
    decorated_func = circuit_breaker_decorator_pulsar(
        max_attempts=max_retries, wait_base=backoff
    )(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if rate_limit is not None and rate_window is not None:
        decorated_func = rate_limit_decorator_pulsar(
            limit=rate_limit, window=rate_window, endpoint=endpoint
        )(decorated_func)
    if permission_roles:
        decorated_func = validate_topic_permissions(
            topic=topic, roles=permission_roles
        )(decorated_func)
    decorated_func = pulsar_task(
        topic=topic, dlq_topic=dlq_topic, priority=task_priority, timeout=task_timeout
    )(decorated_func)

    async def submit(*args, **kwargs) -> Any:
        try:
            req = kwargs.get("request")
            auth_dep = get_auth_dependency(auth_type)
            if credit_amount > 0:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount}, endpoint={endpoint}, priority={task_priority}"
                )
                return await call_function_with_credits(
                    lambda request, user: decorated_func(*args, **kwargs),
                    req,
                    credit_type,
                    credit_amount=credit_amount,
                )
            logger.info(
                f"Submitting Pulsar DB task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}"
            )
            return await decorated_func(*args, **kwargs)
        except InsufficientCreditsError as ice:
            log_and_raise_http_exception(logger, InsufficientCreditsError)
        except RateLimitError as rle:
            log_and_raise_http_exception(logger, RateLimitError)
        except ForbiddenError as fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as ste:
            log_and_raise_http_exception(
                logger, ServiceTimeoutError, endpoint, task_timeout
            )
        except Exception as e:
            logger.exception(
                f"Error in run_db_task_with_best_practices_pulsar.submit: {e}"
            )
            raise APIError(
                status_code=500,
                error_code="internal_error",
                message="An unexpected error occurred.",
                details={"exception": str(e)},
            )

    return submit


def run_cpu_task_with_best_practices_pulsar(
    task_func: Callable[..., Any],
    *,
    config: PulsarCPUTaskConfig,
) -> Callable[..., Any]:
    """
    Register a CPU-bound task as a Pulsar publisher with all best practices, including caching, rate limiting, retries, circuit breaker, metrics, and permissions.
    Usage:
        await run_cpu_task_with_best_practices_pulsar(my_func, config=PulsarCPUTaskConfig())(*args, **kwargs)
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
    cb_timeout = config.cb_timeout
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    topic = config.topic
    dlq_topic = config.dlq_topic
    permission_roles = config.permission_roles

    decorated_func = trace_function()(task_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=500)(decorated_func)
    decorated_func = circuit_breaker_decorator_pulsar(
        max_attempts=max_retries, wait_base=backoff, wait_max=cb_timeout
    )(decorated_func)
    if cache_ttl is not None:
        decorated_func = cache_decorator(RedisClient(), ttl=cache_ttl)(decorated_func)
    if rate_limit is not None and rate_window is not None:
        decorated_func = rate_limit_decorator_pulsar(
            limit=rate_limit, window=rate_window, endpoint=endpoint
        )(decorated_func)
    if permission_roles:
        decorated_func = validate_topic_permissions(
            topic=topic, roles=permission_roles
        )(decorated_func)
    decorated_func = pulsar_task(
        topic=topic, dlq_topic=dlq_topic, priority=task_priority, timeout=task_timeout
    )(decorated_func)

    async def submit(*args, **kwargs) -> Any:
        try:
            req = kwargs.get("request")
            nonlocal credit_amount
            auth_dep = get_auth_dependency(auth_type)
            if auto_estimate_credits and req is not None:
                credit_amount_local = estimate_credits_for_task(task_func, req)
            else:
                credit_amount_local = credit_amount
            if credit_amount_local > 0:
                logger.info(
                    f"Calling function with credits | credit_type={credit_type}, credit_amount={credit_amount_local}, endpoint={endpoint}, priority={task_priority}"
                )
                return await call_function_with_credits(
                    lambda request, user: decorated_func(*args, **kwargs),
                    req,
                    credit_type,
                    credit_amount=credit_amount_local,
                )
            logger.info(
                f"Submitting Pulsar CPU task | args={args}, kwargs={kwargs}, endpoint={endpoint}, priority={task_priority}"
            )
            return await decorated_func(*args, **kwargs)
        except InsufficientCreditsError as ice:
            log_and_raise_http_exception(logger, InsufficientCreditsError)
        except RateLimitError as rle:
            log_and_raise_http_exception(logger, RateLimitError)
        except ForbiddenError as fe:
            log_and_raise_http_exception(logger, ForbiddenError)
        except ServiceTimeoutError as ste:
            log_and_raise_http_exception(
                logger, ServiceTimeoutError, endpoint, task_timeout
            )
        except Exception as e:
            logger.exception(
                f"Error in run_cpu_task_with_best_practices_pulsar.submit: {e}"
            )
            raise APIError(
                status_code=500,
                error_code="internal_error",
                message="An unexpected error occurred.",
                details={"exception": str(e)},
            )

    return submit
