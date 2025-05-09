"""
Authentication utilities for FastAPI endpoints using Supabase as the backend auth provider.
Supports JWT, API key, and OAuth authentication. Uses SupabaseAuthService utilities for validation.
"""

from fastapi import HTTPException, Security, status
from typing import Any, Optional
from app.core.third_party_integrations.supabase_home.sdk.auth import SupabaseAuthService
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader

# Initialize Supabase auth service
supabase_auth_service = SupabaseAuthService()

# Define security schemes as module-level singletons
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


async def authenticate_user(
    jwt_token: str | None = Security(oauth2_scheme, auto_error=False),
    api_key: str | None = Security(api_key_scheme, auto_error=False),
    oauth_token: Optional[
        str
    ] = None,  # For future extensibility, e.g. from a custom header or cookie
) -> dict:
    """
    Authenticate a user using JWT, API key, or OAuth.
    Returns a dict with user info and auth_type ('jwt', 'api_key', or 'oauth').
    Raises 401 if no valid credentials are provided or invalid.
    """
    if jwt_token:
        user = supabase_auth_service.get_user_by_token(jwt_token)
        return {"user": user, "auth_type": "jwt"}
    elif api_key:
        user = supabase_auth_service.get_user_by_token(api_key)
        return {"user": user, "auth_type": "api_key"}
    elif oauth_token:
        # If you support OAuth token directly (e.g., from a callback), use:
        user = supabase_auth_service.get_user_by_token(oauth_token)
        return {"user": user, "auth_type": "oauth"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="No valid credentials"
        )


# Optionally, utility for admin lookup
async def admin_lookup_user(user_id: str) -> dict:
    """
    Retrieve a user by their Supabase UID (admin privileges).
    """
    return supabase_auth_service.get_user(user_id)
