"""
Brute-force protection and token revocation utilities.
- Uses Redis for lockout and token revocation tracking.
- Designed for async FastAPI apps.
- Follows best practices from The Pragmatic Programmer and The Clean Coder.
"""
import time

from fastapi import HTTPException, status

from app.core.valkey_core import client

# Brute-force protection settings
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # seconds (5 minutes)

async def check_brute_force(email: str, ip: str) -> None:
    """
    Checks if the user is locked out due to too many failed login attempts.
    Raises HTTPException if locked out.
    """
    key = f"auth:lockout:{email}:{ip}"
    attempts = await client.get(key)
    if attempts and int(attempts) >= MAX_ATTEMPTS:
        ttl = await client.ttl(key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {ttl} seconds."
        )

async def record_failed_login(email: str, ip: str) -> None:
    """
    Increments failed login attempts for a user and IP. Locks out if threshold exceeded.
    """
    key = f"auth:lockout:{email}:{ip}"
    attempts = await client.incr(key)
    if attempts == 1:
        await client.expire(key, LOCKOUT_TIME)
    if attempts >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Try again in {LOCKOUT_TIME} seconds."
        )

async def reset_failed_login(email: str, ip: str) -> None:
    """
    Resets failed login attempts after a successful login.
    """
    key = f"auth:lockout:{email}:{ip}"
    await client.delete(key)

# Token revocation utilities

async def revoke_token(jti: str, exp: int) -> None:
    """
    Mark a JWT (by its JTI) as revoked until its expiry.
    """
    key = f"auth:revoked:{jti}"
    ttl = exp - int(time.time())
    if ttl > 0:
        await client.set(key, "revoked", ex=ttl)

async def is_token_revoked(jti: str) -> bool:
    """
    Checks if a JWT (by its JTI) is revoked.
    """
    key = f"auth:revoked:{jti}"
    return await client.exists(key) == 1
