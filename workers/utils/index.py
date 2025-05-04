from typing import Any, Callable

from backend.app.api.utils.security.log_sanitization import get_secure_logger
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.api.utils.credits.credits_estimation import (
    estimate_mls_credits,
    estimate_phone_credits,
    estimate_theharvester_credits,
    estimate_zehef_credits,
)
from app.core.db_utils.exceptions.exceptions import log_and_raise_http_exception, ForbiddenError

logger = get_secure_logger("app.core.db_utils.workers.utils")


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


# --- Circuit Breaker Decorator for Pulsar Tasks ---
def circuit_breaker_decorator(
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

    #    --- Permission/Role Validation Decorator (Best Practice) ---


def permission_role_guard(decorated_func, permission_roles: list[str]):
    async def wrapper(*args, **kwargs):
        # Example: check for roles in kwargs or request context
        req = kwargs.get("request")
        user_roles = getattr(req, "user_roles", None) if req else None
        required_roles = permission_roles
        if required_roles and (
            not user_roles or not any(role in user_roles for role in required_roles)
        ):
            logger.warning(
                f"Permission denied: user_roles={user_roles}, required_roles={required_roles}"
            )
            log_and_raise_http_exception(logger, ForbiddenError)
        return await decorated_func(*args, **kwargs)

    return wrapper


# --- Pulsar Task Registration Utilities ---
def _build_user_auth_component(kwargs, permission_roles):
    request = kwargs.get("request", {})
    if hasattr(request, "user") and any(
        role in ["user", "admin"] for role in permission_roles
    ):
        return f"user={request.user.id}"
    return f"auth={request.headers.get('Authorization', 'none')}"
