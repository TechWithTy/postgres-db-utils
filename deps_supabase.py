import logging
from typing import Annotated, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.third_party_integrations.supabase_home.init import get_supabase_client

from app.core.config import settings


security = HTTPBearer(auto_error=False)



async def get_supabase_db():
    """
    Returns configured Supabase client instance using service role
    """
    return get_supabase_client()


async def get_current_supabase_user(authorization: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    """
    Validates JWT and returns user payload using Supabase auth
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
        )
    
    from app.core.third_party_integrations.supabase_home.init import get_supabase_client
    from app.core.third_party_integrations.supabase_home.auth import SupabaseAuthService
    client = get_supabase_client()
    service = SupabaseAuthService()
    try:
        user = service.get_user_by_token(authorization.credentials)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        return user
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication: {str(e)}",
        )


async def get_current_supabase_superuser(request: Request):
    auth_header = request.headers.get("authorization")
    logging.debug(
        f"[get_current_supabase_superuser] Authorization header: {auth_header}"
    )
    if not auth_header or not auth_header.lower().startswith("bearer "):
        logging.warning("[get_current_supabase_superuser] Missing credentials")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Missing credentials"
        )
    token = auth_header[7:]
    try:
        from app.core.third_party_integrations.supabase_home.init import get_supabase_client
        from app.core.third_party_integrations.supabase_home.auth import SupabaseAuthService
        client = get_supabase_client()
        service = SupabaseAuthService()
        user_info = service.get_user_by_token(token)
        user = user_info.get("user", user_info)
        meta = user.get("user_metadata", {})
        app_meta = user.get("app_metadata", {})
        logging.debug(
            f"[get_current_supabase_superuser] user_metadata: {meta}, app_metadata: {app_meta}"
        )
        if not (meta.get("is_superuser") or app_meta.get("is_superuser")):
            logging.warning(
                f"[get_current_supabase_superuser] Not a superuser. meta: {meta}, app_meta: {app_meta}"
            )
            raise HTTPException(
                status_code=403, detail="The user doesn't have enough privileges"
            )
        logging.info(
            f"[get_current_supabase_superuser] Superuser access granted for user: {user.get('email')}"
        )
        return user
    except Exception as e:
        logging.error(f"[get_current_supabase_superuser] Exception: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )


async def get_db_session():
    """
    Returns Supabase client with anon key for user-level access
    """
    return get_supabase_client()
