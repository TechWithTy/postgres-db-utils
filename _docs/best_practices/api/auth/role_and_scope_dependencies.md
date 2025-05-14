# FastAPI Role, Scope, and User-Type Dependency Best Practices

This document explains how to enforce role-based, service-based, and user-type-based access in FastAPI using dependency injection. These patterns help you secure endpoints for users, admins, services, or systems, and enforce OAuth scopes.

---

## 1. Enforcing OAuth Scopes

```python
from fastapi import Request, HTTPException, Depends

def require_scope(required_scope: str):
    def checker(request: Request):
        token_scopes = getattr(request.state, "token_scopes", [])
        if required_scope not in token_scopes:
            raise HTTPException(status_code=403, detail="Insufficient OAuth scope")
    return Depends(checker)
```

- **Usage:**
  - Add `Depends(require_scope("desired_scope"))` to your route dependencies.
  - Returns 403 if the user's token does not include the required scope.

---

## 2. User-Type and Role Dependencies

```python
from fastapi import HTTPException, Depends
from typing import Sequence

# Dependency to get the current user (example, adapt as needed)
async def get_auth_service():
    ...

async def admin_required(current_user: dict = Depends(get_auth_service)):
    if not (
        current_user.get("is_admin")
        or current_user.get("is_system")
        or current_user.get("is_service")
    ):
        raise HTTPException(status_code=403, detail="Admin, system, or service privileges required.")
    return current_user

async def user_required(current_user: dict = Depends(get_auth_service)):
    if not (
        current_user.get("id")
        or current_user.get("is_service")
        or current_user.get("is_system")
    ):
        raise HTTPException(status_code=401, detail="User, system, or service authentication required.")
    return current_user

async def service_required(current_user: dict = Depends(get_auth_service)):
    if not current_user.get("is_service"):
        raise HTTPException(status_code=403, detail="Service privileges required.")
    return current_user

async def system_required(current_user: dict = Depends(get_auth_service)):
    if not current_user.get("is_system"):
        raise HTTPException(status_code=403, detail="System privileges required.")
    return current_user

# Flexible roles dependency

def roles_required(
    allowed_roles: Sequence[str],
    service_access: bool = True,
    system_access: bool = True,
):
    async def dependency(current_user: dict = Depends(get_auth_service)):
        if service_access and current_user.get("is_service", False):
            return current_user
        if system_access and current_user.get("is_system", False):
            return current_user
        user_roles = set(current_user.get("roles", []))
        if not user_roles.intersection(set(allowed_roles)):
            raise HTTPException(status_code=403, detail="Insufficient role privileges.")
        return current_user
    return dependency
```

- **Usage:**
  - Add `Depends(admin_required)` or `Depends(user_required)` to restrict access to admins or users.
  - Use `Depends(service_required)` or `Depends(system_required)` for service/system endpoints.
  - Use `Depends(roles_required(["analyst", "manager"]))` for custom roles.

---

## 3. Best Practices
- Always use dependency injection for access control, not manual checks in route bodies.
- Log all access denials for audit and compliance.
- Document all roles and scopes used in your API.
- Use least-privilege: only grant the minimum roles/scopes needed for each endpoint.
- Test all dependencies with unit and integration tests.

---

*Last updated: 2025-05-13*
