"""
Rate limiting utilities for VAPI endpoints.
"""

import time

from fastapi import HTTPException, status

from app.core.redis import client


async def check_rate_limit(
    token: str, limit: int = 5, window: int = 60, endpoint: str | None = None
) -> None:
    """
    Check and enforce rate limits for VAPI endpoints.

    Args:
        token: The API token or user identifier
        limit: Maximum allowed requests in window
        window: Time window in seconds
        endpoint: Optional endpoint identifier

    Raises:
        HTTPException: 429 if rate limit exceeded
    """
    if not client:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Rate limiting service unavailable",
        )

    key = f"vapi:rate_limit:{token}"
    if endpoint:
        key += f":{endpoint}"

    current = await client.incr(key)
    if current == 1:
        await client.expire(key, window)

    if current > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {window} seconds.",
            headers={"Retry-After": str(window)},
        )
