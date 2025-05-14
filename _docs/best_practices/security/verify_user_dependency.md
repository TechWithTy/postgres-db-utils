# Verifying a User in FastAPI with `get_verified_user`

This guide explains how to use the `get_verified_user` dependency for unified authentication in FastAPI endpoints. This function supports both JWT and API key authentication, returning user details and the authentication type.

---

## Overview
- **Function:** `get_verified_user`
- **Purpose:** Verifies a user via JWT or API key using FastAPI's dependency injection.
- **Returns:** `{"user": user, "auth_type": "jwt"}` or `{"user": user, "auth_type": "api_key"}`
- **Raises:** `HTTPException(401)` if no valid credentials are provided.

---

## Usage with FastAPI

```python
from fastapi import Depends, APIRouter
from app.core.db_utils.security.security import get_verified_user

router = APIRouter()

@router.get("/protected-endpoint")
async def protected_route(
    verified=Depends(get_verified_user)
):
    user = verified["user"]
    auth_type = verified["auth_type"]
    # Your logic here
    return {"user": user, "auth_type": auth_type}
```

---

## How it Works
- **JWT Provided:** If a JWT token is present, the user is validated via `auth_service.get_user_by_token(jwt_token)`. The response includes `auth_type: "jwt"`.

---

## Role-Based Access Control with `permission_role_guard`

You can enforce role-based permissions on your FastAPI endpoints using the `permission_role_guard` utility. This guard checks if the authenticated user has at least one of the required roles before allowing access to the endpoint.

### Example Usage

```python
from fastapi import Depends, APIRouter, Request
from app.core.db_utils.security.security import get_verified_user
from app.core.db_utils.workers.utils.index import permission_role_guard

router = APIRouter()

async def my_protected_logic(request: Request, verified=Depends(get_verified_user)):
    user = verified["user"]
    # Your logic here
    return {"user": user}

# Wrap your logic function with the permission_role_guard
protected_with_roles = permission_role_guard(my_protected_logic, permission_roles=["admin", "superuser"])

@router.get("/admin-endpoint")
async def admin_route(request: Request, verified=Depends(get_verified_user)):
    return await protected_with_roles(request=request, verified=verified)
```

**How it works:**
- The guard checks for `user_roles` on the request (e.g., set by authentication middleware or earlier dependency).
- If the user lacks any of the required roles, a 403 Forbidden error is raised.
- Otherwise, the wrapped function executes as normal.

**Tip:**
- You can use this guard in combination with any FastAPI dependency, including `get_verified_user`, for robust, layered security.
- Log and error handling are built-in for auditability.
- **API Key Provided:** If an API key is present, the user is validated with the same method. The response includes `auth_type: "api_key"`.
- **No Credentials:** Raises 401 Unauthorized.

---

## Best Practices
- Use as a `Depends` dependency in any route that requires user authentication.
- Handles both header-based JWT and API key authentication seamlessly.
- For custom error handling or logging, wrap this dependency in your own function.
- Always check the returned `auth_type` for auditing or conditional logic.

---

## Example: Custom Wrapper

```python
from fastapi import Depends, HTTPException
from app.core.db_utils.security.security import get_verified_user

async def get_active_user(verified=Depends(get_verified_user)):
    user = verified["user"]
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Inactive user")
    return user
```

---

## Security Notes
- Do not expose sensitive user information in logs or responses.
- Always use HTTPS in production.
- Rotate API keys and JWT secrets regularly.

---

*Last updated: 2025-05-13*
