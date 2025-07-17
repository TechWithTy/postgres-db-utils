# backend/app/core/db_utils/workers/services/auth.py
from typing import Any

from gotrue.errors import AuthApiError
from supabase_py_async import AsyncClient

from app.logging_config import get_logger

logger = get_logger(__name__)


class AuthError(Exception):
    """Custom exception for authentication errors."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class SupabaseAuthService:
    """Service for handling Supabase authentication and user management."""

    def __init__(self, supabase_client: AsyncClient):
        self._client = supabase_client

    async def get_user_from_token(self, token: str) -> Any:
        """Get user from a JWT token."""
        try:
            user_response = await self._client.auth.get_user(token)
            if not user_response or not user_response.user:
                raise AuthError("Invalid or expired token.")
            return user_response.user
        except AuthApiError as e:
            logger.error(f"Supabase auth error: {e.message}", exc_info=True)
            raise AuthError(f"Authentication failed: {e.message}") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred during token validation: {e}", exc_info=True)
            raise AuthError("An unexpected error occurred.") from e

    async def get_user_roles(self, user: Any) -> list[str]:
        """Extract user roles from user metadata."""
        if not user or not hasattr(user, "user_metadata"):
            return []
        return user.user_metadata.get("roles", [])
