# FastAPI OAuth Scopes & Role-Based Access Integration: Best Practices

This document integrates FastAPI's native OAuth2 scopes with your custom role, service, and user-type dependencies. It provides a unified approach for securing APIs with both standards-based and business-specific access controls.

---

## 1. Why Combine OAuth Scopes and Role Dependencies?
- **OAuth scopes** allow granular, standards-based permissioning for API tokens (e.g., "read:users", "write:admin").
- **Role/user-type dependencies** enforce business rules (e.g., admin, analyst, service, system) and custom logic.
- Combining both ensures:
  - Compatibility with third-party OAuth clients
  - Enforcement of your business's privilege model
  - DRY, auditable, and reusable access logic

---

## 2. Unified Dependency Patterns

```python
from fastapi import Request, HTTPException, Depends
from typing import Sequence

# --- OAuth Scope Dependency ---
def require_scope(required_scope: str):
    def checker(request: Request):
        token_scopes = getattr(request.state, "token_scopes", [])
        if required_scope not in token_scopes:
            raise HTTPException(status_code=403, detail="Insufficient OAuth scope")
    return Depends(checker)

# --- Role/User-Type Dependencies ---
async def get_auth_service():
    ...  # Your implementation

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

# --- Flexible Roles Dependency ---
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

---

## 3. Usage Examples

**Require both OAuth scope and admin privileges:**
```python
@app.get("/admin/data")
def get_admin_data(
    user=Depends(admin_required),
    scope=Depends(require_scope("admin:read")),
):
    ...
```

**Require analyst or manager roles and a specific scope:**
```python
@app.get("/reports")
def get_reports(
    user=Depends(roles_required(["analyst", "manager"])),
    scope=Depends(require_scope("reports:read")),
):
    ...
```

---

## 4. Best Practices
- Always use dependency injection for access control—never perform manual checks inside route handlers.
- Combine scopes and roles for maximum security and flexibility.
- Log all access denials and suspicious activity for audit and compliance.
- Document all roles and scopes in your API reference.
- Use least-privilege: only grant the minimum roles/scopes needed per endpoint.
- Test all access dependencies with unit and integration tests.

---

*Last updated: 2025-05-13*
