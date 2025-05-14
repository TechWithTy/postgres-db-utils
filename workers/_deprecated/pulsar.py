# --- Pulsar Worker Utilities (Celery-Independent, Best Practices) ---
import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from app.api.utils.credits.credits import call_function_with_credits
from app.api.utils.security.log_sanitization import get_secure_logger
from app.core.db_utils.exceptions.exceptions import (
    ForbiddenError,
    log_and_raise_http_exception,
)
from app.core.db_utils.workers._schemas import (
    PulsarCPUTaskConfig,
    PulsarDBTaskConfig,
    PulsarIOTaskConfig,
)
from app.core.db_utils.workers.utils.index import (
    _build_user_auth_component,
    estimate_credits_for_task,
    permission_role_guard,
)
from app.core.pulsar.decorators import (
    pulsar_task,
    validate_topic_permissions,
)
from app.core.redis.rate_limit import service_rate_limit, verify_and_limit
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)

logger = get_secure_logger("app.core.db_utils.workers.pulsar")




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
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    max_retries = config.max_retries or 1
    backoff = config.backoff or 1
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles
    topic = config.topic
    dlq_topic = getattr(config, "dlq_topic", None)

    decorated_func = task_func
    decorated_func = trace_function()(decorated_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    if rate_limit and rate_window:
        decorated_func = service_rate_limit(rate_limit, rate_window, endpoint=endpoint)(
            decorated_func
        )
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)
    if topic:
        decorated_func = pulsar_task(
            topic=topic,
            max_retries=max_retries,
            retry_delay=backoff,
            dlq_topic=dlq_topic,
        )(decorated_func)
        decorated_func = validate_topic_permissions(topic)(decorated_func)

    async def submit(*args, **kwargs):
        req = kwargs.get("request")
        user_auth_component = _build_user_auth_component(req) if req else None
        await verify_and_limit(
            service_rate_limit(
                limit=rate_limit or 100,
                window=rate_window or 60,
                endpoint=endpoint or "pulsar_io",
                user=user_auth_component,
            )
        )
        attempt = 0
        while attempt < max_retries:
            try:
                if credit_amount and req:
                    result = await call_function_with_credits(
                        lambda request, user: decorated_func(*args, **kwargs),
                        req,
                        credit_type or "io_task",
                        credit_amount,
                    )
                else:
                    result = await decorated_func(*args, **kwargs)
                logger.info(
                    f"I/O task succeeded | endpoint={endpoint}, topic={topic}, priority={task_priority}, cache_ttl={cache_ttl}, task_timeout={task_timeout}, dlq_topic={dlq_topic}"
                )
                return result
            except ForbiddenError as exc:
                log_and_raise_http_exception(exc)
            except Exception as e:
                attempt += 1
                logger.error(
                    f"I/O task attempt {attempt} failed | endpoint={endpoint}, error={e}, retrying in {backoff}s"
                )
                if attempt >= max_retries:
                    logger.error(
                        f"I/O task failed after {attempt} attempts | endpoint={endpoint}"
                    )
                    raise
                await asyncio.sleep(backoff)

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
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    max_retries = config.max_retries or 1
    backoff = config.backoff or 1
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles
    topic = config.topic
    dlq_topic = getattr(config, "dlq_topic", None)

    decorated_func = task_func
    decorated_func = trace_function()(decorated_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    if rate_limit and rate_window:
        decorated_func = service_rate_limit(rate_limit, rate_window, endpoint=endpoint)(
            decorated_func
        )
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)
    if topic:
        decorated_func = pulsar_task(
            topic=topic,
            max_retries=max_retries,
            retry_delay=backoff,
            dlq_topic=dlq_topic,
        )(decorated_func)
        decorated_func = validate_topic_permissions(topic)(decorated_func)

    async def submit(*args, **kwargs):
        req = kwargs.get("request")
        user_auth_component = _build_user_auth_component(req) if req else None
        credits_needed = credit_amount
        await verify_and_limit(
            service_rate_limit(
                limit=rate_limit or 100,
                window=rate_window or 60,
                endpoint=endpoint or "pulsar_db",
                user=user_auth_component,
            )
        )
        attempt = 0
        while attempt < max_retries:
            try:
                if credits_needed and req:
                    result = await call_function_with_credits(
                        lambda request, user: decorated_func(*args, **kwargs),
                        req,
                        credit_type or "db_task",
                        credits_needed,
                    )
                else:
                    result = await decorated_func(*args, **kwargs)
                logger.info(
                    f"DB task succeeded | endpoint={endpoint}, topic={topic}, priority={task_priority}, cache_ttl={cache_ttl}, task_timeout={task_timeout}, dlq_topic={dlq_topic}"
                )
                return result
            except ForbiddenError as exc:
                log_and_raise_http_exception(exc)
            except Exception as e:
                attempt += 1
                logger.error(
                    f"DB task attempt {attempt} failed | endpoint={endpoint}, error={e}, retrying in {backoff}s"
                )
                if attempt >= max_retries:
                    logger.error(
                        f"DB task failed after {attempt} attempts | endpoint={endpoint}"
                    )
                    raise
                await asyncio.sleep(backoff)

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
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    rate_window = config.rate_window
    max_retries = config.max_retries or 1
    backoff = config.backoff or 1
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles
    topic = config.topic
    dlq_topic = getattr(config, "dlq_topic", None)
    auto_estimate_credits = getattr(config, "auto_estimate_credits", False)

    decorated_func = task_func
    decorated_func = trace_function()(decorated_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    if rate_limit and rate_window:
        decorated_func = service_rate_limit(rate_limit, rate_window, endpoint=endpoint)(
            decorated_func
        )
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)
    if topic:
        decorated_func = pulsar_task(
            topic=topic,
            max_retries=max_retries,
            retry_delay=backoff,
            dlq_topic=dlq_topic,
        )(decorated_func)
        decorated_func = validate_topic_permissions(topic)(decorated_func)

    async def submit(*args, **kwargs):
        req = kwargs.get("request")
        user_auth_component = _build_user_auth_component(req) if req else None
        # Use estimate_credits_for_task only if auto_estimate_credits is True
        if auto_estimate_credits and req:
            credits_needed = estimate_credits_for_task(task_func, req)
        else:
            credits_needed = credit_amount
        await verify_and_limit(
            service_rate_limit(
                limit=rate_limit or 100,
                window=rate_window or 60,
                endpoint=endpoint or "pulsar_cpu",
                user=user_auth_component,
            )
        )
        attempt = 0
        while attempt < max_retries:
            try:
                if credits_needed and req:
                    result = await call_function_with_credits(
                        lambda request, user: decorated_func(*args, **kwargs),
                        req,
                        credit_type or "cpu_task",
                        credits_needed,
                    )
                else:
                    result = await decorated_func(*args, **kwargs)
                logger.info(
                    f"CPU task succeeded | endpoint={endpoint}, topic={topic}, priority={task_priority}, cache_ttl={cache_ttl}, task_timeout={task_timeout}, dlq_topic={dlq_topic}"
                )
                return result
            except ForbiddenError as exc:
                log_and_raise_http_exception(exc)
            except Exception as e:
                attempt += 1
                logger.error(
                    f"CPU task attempt {attempt} failed | endpoint={endpoint}, error={e}, retrying in {backoff}s"
                )
                if attempt >= max_retries:
                    logger.error(
                        f"CPU task failed after {attempt} attempts | endpoint={endpoint}"
                    )
                    raise
                await asyncio.sleep(backoff)

    return submit
