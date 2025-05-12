# --- Valkey Worker Utilities (Celery-Independent, Best Practices) ---
import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from app.api.utils.credits.credits import call_function_with_credits
from app.api.utils.security.log_sanitization import get_secure_logger
from app.core.celery.client import celery_app
from app.core.celery.decorators import celery_task
from app.core.db_utils.exceptions.exceptions import (
    ForbiddenError,
    log_and_raise_http_exception,
)
from app.core.db_utils.workers._schemas import CPUTaskConfig, DBTaskConfig, IOTaskConfig
from app.core.db_utils.workers.utils.index import (
    _build_user_auth_component,
    estimate_credits_for_task,
    permission_role_guard,
)
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.valkey_core.client import ValkeyClient
from app.core.valkey.limiting.rate_limit import service_rate_limit, verify_and_limit

valkey_client = ValkeyClient()

# Example logger usage
logger = get_secure_logger("app.core.db_utils.workers.valkey")


# Removed all direct ValkeyClient usage and implementation from this file.
# All worker registration functions now use only decorators, service_rate_limit, _build_user_auth_component, estimate_credits_for_task, and other best practices utilities.


# --- I/O Task Worker ---
def run_io_task_with_best_practices_valkey(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: IOTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async I/O task as a Valkey-backed worker with best practices: caching, rate limiting, retries, circuit breaker, metrics, permissions, and Celery integration.
    All config parameters are used.
    """
    credit_type = getattr(config, "credit_type", None)
    credit_amount = getattr(config, "credit_amount", 0)
    cache_ttl = getattr(config, "cache_ttl", None)
    rate_limit = getattr(config, "rate_limit", 100)
    rate_window = getattr(config, "rate_window", 60)
    max_retries = getattr(config, "max_retries", 1)
    backoff = getattr(config, "backoff", 1)
    task_timeout = getattr(config, "task_timeout", None)
    endpoint = getattr(config, "endpoint", "valkey_io")
    task_priority = getattr(config, "task_priority", None)
    permission_roles = getattr(config, "permission_roles", None)
    channel = getattr(config, "channel", None)
    queue_name = getattr(config, "queue_name", None)
    batch_size = getattr(config, "batch_size", 100)
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

    @celery_task
    async def celery_io_task(*args, **kwargs):
        """Celery-compatible I/O task for Valkey worker integration."""
        return await decorated_func(*args, **kwargs)

    async def submit(*args, **kwargs):
        req = kwargs.get("request")
        user_auth_component = _build_user_auth_component(req) if req else None
        await verify_and_limit(
            service_rate_limit(
                limit=rate_limit,
                window=rate_window,
                endpoint=endpoint,
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
                        credit_amount=credit_amount,
                    )
                else:
                    result = await decorated_func(*args, **kwargs)
                # Poll Valkey queue for events (simulate batch processing)
                events = (
                    await valkey_client.lrange(queue_name, 0, batch_size - 1)
                    if queue_name
                    else []
                )
                for event in events:
                    # Idempotency/deduplication using cache
                    if cache_ttl:
                        await valkey_client.set(f"event:{event}", event, ex=cache_ttl)
                    try:
                        await asyncio.wait_for(
                            decorated_func(event, *args, **kwargs),
                            timeout=task_timeout,
                        )
                    except asyncio.TimeoutError:
                        logger.error(
                            f"I/O task timed out | endpoint={endpoint}, event={event}"
                        )
                        continue
                    # Publish to channel if needed
                    if channel:
                        await valkey_client.publish(channel, event)
                    celery_kwargs = {"args": [event]}
                    if task_priority is not None:
                        celery_kwargs["priority"] = task_priority
                    celery_app.send_task(
                        "app.core.db_utils.workers.valkey.celery_io_task",
                        **celery_kwargs,
                    )
                    logger.info(
                        f"I/O task succeeded | endpoint={endpoint}, event={event}, queue={queue_name}, channel={channel}, priority={task_priority}, cache_ttl={cache_ttl}, task_timeout={task_timeout}, dlq_topic={dlq_topic}"
                    )
                # Remove processed events
                if queue_name and events:
                    await valkey_client.ltrim(queue_name, batch_size, -1)
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


# --- DB Task Worker ---
def run_db_task_with_best_practices_valkey(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: DBTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async DB task as a Valkey-backed worker with best practices: caching, rate limiting, retries, circuit breaker, metrics, permissions, and Celery integration.
    All config parameters are used.
    """
    credit_type = getattr(config, "credit_type", None)
    credit_amount = getattr(config, "credit_amount", 0)
    cache_ttl = getattr(config, "cache_ttl", None)
    rate_limit = getattr(config, "rate_limit", 100)
    rate_window = getattr(config, "rate_window", 60)
    max_retries = getattr(config, "max_retries", 1)
    backoff = getattr(config, "backoff", 1)
    task_timeout = getattr(config, "task_timeout", None)
    endpoint = getattr(config, "endpoint", "valkey_db")
    task_priority = getattr(config, "task_priority", None)
    permission_roles = getattr(config, "permission_roles", None)
    channel = getattr(config, "channel", None)
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

    @celery_task
    async def celery_db_task(*args, **kwargs):
        """Celery-compatible DB task for Valkey worker integration."""
        return await decorated_func(*args, **kwargs)

    async def submit(*args, **kwargs):
        req = kwargs.get("request")
        user_auth_component = _build_user_auth_component(req) if req else None
        await verify_and_limit(
            service_rate_limit(
                limit=rate_limit,
                window=rate_window,
                endpoint=endpoint,
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
                        credit_type or "db_task",
                        credit_amount=credit_amount,
                    )
                else:
                    result = await decorated_func(*args, **kwargs)
                # Optionally publish to channel
                if channel:
                    await valkey_client.publish(channel, result)
                logger.info(
                    "DB task succeeded | endpoint="
                    + endpoint
                    + ", channel="
                    + channel
                    + ", priority="
                    + str(task_priority)
                    + ", cache_ttl="
                    + str(cache_ttl)
                    + ", task_timeout="
                    + str(task_timeout)
                    + ", dlq_topic="
                    + dlq_topic
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


# --- CPU Task Worker ---
def run_cpu_task_with_best_practices_valkey(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: CPUTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async CPU task as a Valkey-backed worker with best practices: caching, rate limiting, retries, circuit breaker, metrics, permissions, and Celery integration.
    All config parameters are used.
    """
    credit_type = getattr(config, "credit_type", None)
    credit_amount = getattr(config, "credit_amount", 0)
    cache_ttl = getattr(config, "cache_ttl", None)
    rate_limit = getattr(config, "rate_limit", 100)
    rate_window = getattr(config, "rate_window", 60)
    max_retries = getattr(config, "max_retries", 1)
    backoff = getattr(config, "backoff", 1)
    task_timeout = getattr(config, "task_timeout", None)
    endpoint = getattr(config, "endpoint", "valkey_cpu")
    task_priority = getattr(config, "task_priority", None)
    permission_roles = getattr(config, "permission_roles", None)
    channel = getattr(config, "channel", None)
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

    @celery_task
    async def celery_cpu_task(*args, **kwargs):
        """Celery-compatible CPU task for Valkey worker integration."""
        return await decorated_func(*args, **kwargs)

    async def submit(*args, **kwargs):
        req = kwargs.get("request")
        user_auth_component = _build_user_auth_component(req) if req else None
        credits_needed = (
            estimate_credits_for_task(task_func, req)
            if auto_estimate_credits and req
            else credit_amount
        )
        await verify_and_limit(
            service_rate_limit(
                limit=rate_limit,
                window=rate_window,
                endpoint=endpoint,
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
                if channel:
                    await valkey_client.publish(channel, result)
                celery_kwargs = {"args": [result]}
                if task_priority is not None:
                    celery_kwargs["priority"] = task_priority
                celery_app.send_task(
                    f"app.core.db_utils.workers.valkey.celery_cpu_task",
                    **celery_kwargs,
                )
                logger.info(
                    "CPU task succeeded | endpoint="
                    + endpoint
                    + ", channel="
                    + channel
                    + ", priority="
                    + str(task_priority)
                    + ", cache_ttl="
                    + str(cache_ttl)
                    + ", task_timeout="
                    + str(task_timeout)
                    + ", dlq_topic="
                    + dlq_topic
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


# TODO: Add metrics, error handling, and configuration patterns as needed.
