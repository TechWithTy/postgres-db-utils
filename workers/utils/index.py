from typing import Any, Callable

from app.core.db_utils.security.log_sanitization import get_secure_logger




# --- Pulsar Task Registration Utilities ---
def _build_user_auth_component(kwargs, permission_roles):
    request = kwargs.get("request", {})
    if hasattr(request, "user") and any(
        role in ["user", "admin"] for role in permission_roles
    ):
        return f"user={request.user.id}"
    return f"auth={request.headers.get('Authorization', 'none')}"
