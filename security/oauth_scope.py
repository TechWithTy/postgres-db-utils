from fastapi import Request, HTTPException, Depends

from typing import Sequence

from app.core.db_utils.exceptions.exceptions import log_and_raise_http_exception, ForbiddenError
from app.core.db_utils.security.log_sanitization import get_secure_logger

logger = get_secure_logger("app.core.db_utils.security.oauth_scope")

def require_scope(required_scope: str):
    def checker(request: Request):
        token_scopes = getattr(request.state, "token_scopes", [])
        if required_scope not in token_scopes:
            raise HTTPException(status_code=403, detail="Insufficient OAuth scope")

    return Depends(checker)


# --- Dependency helpers ---
from app.core.third_party_integrations.supabase_home.sdk.auth import SupabaseAuthService
from app.core.third_party_integrations.supabase_home.client import get_supabase_client

async def get_auth_service():
    client = await get_supabase_client()
    service = SupabaseAuthService(client)
    user = await service.get_current_user() if hasattr(service.get_current_user, '__await__') else service.get_current_user()
    return user

async def admin_required(current_user: dict = Depends(get_auth_service)):
    if not (
        current_user.get("is_admin")
        or current_user.get("is_system")
        or current_user.get("is_service")
    ):
        raise HTTPException(
            status_code=403, detail="Admin, system, or service privileges required."
        )
    return current_user


async def user_required(current_user: dict = Depends(get_auth_service)):
    if not (
        current_user.get("id")
        or current_user.get("is_service")
        or current_user.get("is_system")
    ):
        raise HTTPException(
            status_code=401, detail="User, system, or service authentication required."
        )
    return current_user


async def service_required(current_user: dict = Depends(get_auth_service)):
    if not current_user.get("is_service"):
        raise HTTPException(status_code=403, detail="Service privileges required.")
    return current_user


async def system_required(current_user: dict = Depends(get_auth_service)):
    if not current_user.get("is_system"):
        raise HTTPException(status_code=403, detail="System privileges required.")
    return current_user


def roles_required(
    allowed_roles: Sequence[str],
    service_access: bool = True,
    system_access: bool = True,
):
    async def dependency(current_user: dict = Depends(get_auth_service)):
        # Check for service or system access if enabled
        if service_access and current_user.get("is_service", False):
            return current_user
        if system_access and current_user.get("is_system", False):
            return current_user

        # Otherwise check for role-based access
        user_roles = set(current_user.get("roles", []))
        if not user_roles.intersection(set(allowed_roles)):
            raise HTTPException(status_code=403, detail="Insufficient role privileges.")
        return current_user

    return dependency

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