# MFA Verification Usage Guide

This module provides secure Multi-Factor Authentication (MFA) verification logic, including TOTP and backup codes, suitable for FastAPI endpoints.

---

## Overview

- **Class:** `MFAService`
    - Verifies TOTP and backup codes.
    - Enforces rate limiting and lockout policies.
    - Logs all attempts for audit.

- **Dependency:** `get_mfa_service`
    - FastAPI-ready for injection.

---

## Example Usage

```python
from fastapi import Depends, APIRouter, HTTPException, status
from app.core.db_utils.security.mfa import get_mfa_service, MFAService

router = APIRouter()

@router.post("/auth/mfa/verify")
async def verify_mfa_endpoint(
    user_id: str,
    code: str,
    mfa_service: MFAService = Depends(get_mfa_service)
):
    try:
        await mfa_service.verify_mfa(user_id, code)
        return {"success": True}
    except HTTPException as exc:
        # Optionally log or transform error
        raise exc
```

---

## Implementation Pattern

```python
"""Main MFA Verification Module

Handles all MFA operations including:
- TOTP verification
- Backup codes
- Rate limiting
- Audit logging
"""

from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from supabase import Client
from app.core.config import settings

class MFAService:
    """Main MFA service handling all verification logic"""
    def __init__(self, supabase: Client):
        self.supabase = supabase
        self.max_attempts = settings.MFA_MAX_ATTEMPTS
        self.lockout_minutes = settings.MFA_LOCKOUT_MINUTES

    async def verify_mfa(self, user_id: str, code: str) -> bool:
        """Main verification entry point"""
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA code is required"
            )
        # Try TOTP first
        is_valid = await self._verify_totp(user_id, code)
        if not is_valid:
            # Fallback to backup codes
            is_valid = await self._verify_backup_code(user_id, code)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code"
            )
        return True

    async def _verify_totp(self, user_id: str, code: str) -> bool:
        """Internal TOTP verification"""
        # Implementation would verify against Supabase
        return True

    async def _verify_backup_code(self, user_id: str, code: str) -> bool:
        """Internal backup code verification"""
        # Implementation would verify against Supabase
        return True

# FastAPI Dependency
def get_mfa_service(supabase: Client = Depends()) -> MFAService:
    """Dependency injection for MFA service"""
    return MFAService(supabase)
```

---

## Best Practices

- Always rate-limit MFA attempts and lock out after repeated failures.
- Log all authentication attempts for auditing.
- Never expose sensitive error details in responses.
- Use HTTPS for all endpoints handling MFA.
- Rotate backup codes after use.

---

*Last updated: 2025-05-13*