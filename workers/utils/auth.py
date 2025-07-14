# backend/app/core/db_utils/workers/utils/auth.py
from typing import Any

from fastapi import Depends, HTTPException, status

from app.core.db_utils.workers.dependencies import get_auth_service, get_current_user
from app.core.db_utils.workers.services.auth import SupabaseAuthService


def roles_required(required_roles: list[str]):
    """
    Dependency that checks if a user has at least one of the required roles.
    Allows users with the 'admin' role to bypass the check.
    """

    async def role_checker(
        user: Any = Depends(get_current_user),
        auth_service: SupabaseAuthService = Depends(get_auth_service),
    ) -> Any:
        user_roles = await auth_service.get_user_roles(user)

        # Admin role bypasses all checks
        if "admin" in user_roles:
            return user

        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return user

    return role_checker
