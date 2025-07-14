# backend/app/core/db_utils/workers/dependencies.py
import os
from functools import lru_cache
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from supabase_py_async import AsyncClient, create_client

from app.core.db_utils.workers.services.auth import AuthError, SupabaseAuthService
from app.logging_config import get_logger

logger = get_logger(__name__)


@lru_cache
def get_supabase_client() -> AsyncClient:
    """Create and return a Supabase client instance."""
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_KEY")
    if not supabase_url or not supabase_key:
        logger.error("Supabase URL or Key not found in environment variables.")
        raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set.")
    return create_client(supabase_url, supabase_key)


async def get_auth_service(
    client: AsyncClient = Depends(get_supabase_client),
) -> SupabaseAuthService:
    """Dependency to get the SupabaseAuthService."""
    return SupabaseAuthService(client)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)


async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    auth_service: SupabaseAuthService = Depends(get_auth_service),
) -> Any:
    """Dependency to get the current user from a JWT token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return await auth_service.get_user_from_token(token)
    except AuthError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        ) from e
