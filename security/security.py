from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, Security, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
api_key_scheme = APIKeyHeader(name="X-API-KEY", auto_error=False)

from app.core.config import settings
from app.core.db_utils.encryption import DataEncryptor
from app.core.redis.rate_limit import (
    get_remaining_limit,
    increment_rate_limit,
    service_rate_limit,
)
from app.core.third_party_integrations.supabase_home.sdk.auth import SupabaseAuthService

# Initialize encryptor - handles both encryption and password hashing
encryptor = DataEncryptor()

ALGORITHM = "HS256"  # Still needed for JWT signatures

# Rate limits (requests per minute)
TOKEN_CREATION_LIMIT = 30
PASSWORD_ATTEMPT_LIMIT = 10


def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    """Rate limited token creation"""
    identifier = f"token_create:{subject}"
    if not service_rate_limit(identifier, TOKEN_CREATION_LIMIT, 60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Token creation rate limit exceeded",
        )

    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    return jwt.encode(
        encryptor.encrypt(to_encode), settings.SECRET_KEY, algorithm=ALGORITHM
    )


def verify_password(plain_password: str, encrypted_hash: str, identifier: str) -> bool:
    """Rate limited password verification"""
    attempt_key = f"pwd_attempt:{identifier}"
    remaining = get_remaining_limit(attempt_key, "auth", PASSWORD_ATTEMPT_LIMIT)

    if remaining <= 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password attempts",
        )

    result = encryptor.verify_hash(plain_password, encrypted_hash)
    increment_rate_limit(attempt_key, "auth")
    return result


def get_password_hash(password: str) -> str:
    """Create password hash with encryption"""
    return encryptor.create_hash(password)


# --- Unified Auth Dependency ---
from app.core.third_party_integrations.supabase_home.app import get_supabase_client

async def get_auth_service():
    client = await get_supabase_client()
    return SupabaseAuthService(client)


async def get_verified_user(
    jwt_token: str = Security(oauth2_scheme),
    api_key: str = Security(api_key_scheme),
    auth_service: SupabaseAuthService = Security(get_auth_service),
):
    """
    Unified dependency for verifying user via JWT or API key.
    Returns a dict with user info and auth_type ('jwt' or 'api_key').
    Raises 401 if no valid credentials are provided.
    """
    if jwt_token:
        user = auth_service.get_user_by_token(jwt_token)
        return {"user": user, "auth_type": "jwt"}
    elif api_key:
        user = auth_service.get_user_by_token(api_key)
        return {"user": user, "auth_type": "api_key"}
    else:
        raise HTTPException(status_code=401, detail="No valid credentials")
