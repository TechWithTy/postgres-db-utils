"""
Valkey + Pulsar + Celery Integration Utilities (Best Practices)
=======================================================================

This module provides production-grade worker registration utilities that bridge Valkey (as a Redis-compatible cache, queue, and pub/sub backend), Apache Pulsar (for streaming), and Celery (for distributed task processing).

NOTE: This module does NOT instantiate Valkey, Pulsar, or Celery clients. Pass in your own configured client objects.
"""

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
from app.core.pulsar.client import PulsarClient
from app.core.pulsar.decorators import (
    pulsar_task,
    validate_topic_permissions,
)
from app.core.telemetry.decorators import (
    measure_performance,
    trace_function,
    track_errors,
)
from app.core.valkey.client import ValkeyClient
from app.core.valkey.limiting.rate_limit import service_rate_limit, verify_and_limit

logger = get_secure_logger("app.core.db_utils.workers.valkey_pulsar")

# Setup ValkeyClient and PulsarClient as global singletons
valkey_client = ValkeyClient()
pulsar_client = PulsarClient()


# Example: Use celery_task decorator for a Celery-compatible function
@celery_task
async def example_celery_io_task(*args, **kwargs):
    """
    Example Celery-compatible I/O task for Valkey/Pulsar worker integration.
    """
    # This task can be referenced by name in celery_app.send_task
    pass


# In worker registration, optionally reference the celery_task-decorated function by name:
# celery_app.send_task("app.core.db_utils.workers.valkey-pulsar.example_celery_io_task", args=[event])


# # Optionally, demonstrate cache usage for idempotency or deduplication
# @cache(ttl=60)
# async def idempotent_event_handler(event):
#     """
#     Example cached handler for idempotency/deduplication.
#     """
#     # ... process event ...
#     pass


# --- I/O Task Worker ---
def run_io_task_with_best_practices_valkey_pulsar(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: PulsarIOTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async I/O task as a worker that consumes from Valkey, publishes to Pulsar, and can enqueue Celery tasks.
    Uses all config parameters for best practices.
    """
    # Extract config values
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
    channel = getattr(config, "channel", None)
    dlq_topic = getattr(config, "dlq_topic", None)
    topic = config.topic
    batch_size = config.batch_size or 100

    decorated_func = task_func
    decorated_func = trace_function()(decorated_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    # Use rate_limit and rate_window from config
    if rate_limit and rate_window:
        decorated_func = service_rate_limit(rate_limit, rate_window, endpoint=endpoint)(
            decorated_func
        )
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)
    # Add Pulsar decorators for best practices, set dlq_topic
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
                endpoint=endpoint or "valkey_io",
                user=user_auth_component,
            )
        )
        attempt = 0
        while attempt < max_retries:
            try:
                if credit_amount and req:
                    return await call_function_with_credits(
                        lambda request, user: decorated_func(*args, **kwargs),
                        req,
                        credit_type or "io_task",
                        credit_amount=credit_amount,
                    )
                # Retry logic for Valkey lrange with backoff
                for attempt in range(max_retries):
                    try:
                        events = await valkey_client.lrange(
                            dlq_topic, 0, batch_size - 1
                        )
                        break
                    except Exception as _e:
                        if attempt == max_retries - 1:
                            raise
                        await asyncio.sleep(backoff)
                else:
                    events = []
                if events:
                    for event in events:
                        # Optionally cache event with TTL for idempotency/deduplication
                        await valkey_client.set(f"event:{event}", event, ex=cache_ttl)
                        try:
                            await asyncio.wait_for(
                                decorated_func(event, *args, **kwargs),
                                timeout=task_timeout,
                            )
                        except asyncio.TimeoutError:
                            # Optionally log or handle timeout
                            continue
                        if topic:
                            await valkey_client.publish(channel, event)
                        celery_kwargs = {"args": [event]}
                        if task_priority is not None:
                            celery_kwargs["priority"] = task_priority
                        celery_app.send_task(
                            "app.core.db_utils.workers.valkey-pulsar.example_celery_io_task",
                            **celery_kwargs,
                        )
                        logger.info(
                            f"I/O task succeeded | endpoint={endpoint}, topic={topic}, priority={task_priority}, cache_ttl={cache_ttl}, task_timeout={task_timeout}, dlq_topic={dlq_topic}"
                        )
                    await valkey_client.ltrim(dlq_topic, batch_size, -1)
                return
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
def run_db_task_with_best_practices_valkey_pulsar(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: PulsarDBTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async DB task as a worker that can publish results to Pulsar, with all best practices (decorators for retry, topic permissions, metrics, etc).
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
    dlq_topic = getattr(config, "dlq_topic", None)
    topic = config.topic
    channel = getattr(config, "channel", None)

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
    # Add Pulsar decorators for best practices, set dlq_topic
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
                endpoint=endpoint or "valkey_db",
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
                if valkey_client and channel:
                    await valkey_client.publish(channel, result)
                if pulsar_client and topic:
                    await pulsar_client.send_message(topic, result)
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


# --- CPU Task Worker ---
def run_cpu_task_with_best_practices_valkey_pulsar(
    task_func: Callable[..., Awaitable[Any]],
    *,
    config: PulsarCPUTaskConfig,
) -> Callable[..., Awaitable[Any]]:
    """
    Register an async CPU task as a worker that can publish results to both Valkey pub/sub, Pulsar, and enqueue Celery tasks.
    Uses all config parameters for best practices.
    """
    # Extract config values
    credit_type = config.credit_type
    credit_amount = config.credit_amount or 0
    cache_ttl = config.cache_ttl
    rate_limit = config.rate_limit
    auto_estimate_credits = config.auto_estimate_credits
    rate_window = config.rate_window
    max_retries = config.max_retries or 1
    backoff = config.backoff or 1
    task_timeout = config.task_timeout
    endpoint = config.endpoint
    task_priority = config.task_priority
    permission_roles = config.permission_roles
    channel = getattr(config, "channel", None)
    dlq_topic = getattr(config, "dlq_topic", None)
    topic = config.topic

    decorated_func = task_func
    decorated_func = trace_function()(decorated_func)
    decorated_func = track_errors(decorated_func)
    decorated_func = measure_performance(threshold_ms=200)(decorated_func)
    # Use rate_limit and rate_window from config
    if rate_limit and rate_window:
        decorated_func = service_rate_limit(rate_limit, rate_window, endpoint=endpoint)(
            decorated_func
        )
    if permission_roles:
        decorated_func = permission_role_guard(decorated_func, permission_roles)
    # Add Pulsar decorators for best practices, set dlq_topic
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
                endpoint=endpoint or "valkey_cpu",
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
                if valkey_client and channel:
                    await valkey_client.publish(channel, result)
                if pulsar_client and topic:
                    await pulsar_client.send_message(topic, result)
                celery_kwargs = {"args": [result]}
                if task_priority is not None:
                    celery_kwargs["priority"] = task_priority
                celery_app.send_task(
                    "app.core.db_utils.workers.valkey-pulsar.example_celery_io_task",
                    **celery_kwargs,
                )
                logger.info(
                    f"CPU task succeeded | endpoint={endpoint}, channel={channel}, topic={topic}, priority={task_priority}, cache_ttl={cache_ttl}, task_timeout={task_timeout}, dlq_topic={dlq_topic}"
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
