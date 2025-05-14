# OAuth Scope & Role-Based Access Best Practices

- Restrict access to endpoints based on OAuth scopes and roles.
- Use dependency injection to enforce permissions.
- Log all access denials for audit.

---

## Example: FastAPI Entrypoint

```python
from fastapi import Depends
from app.core.db_utils.security.oauth_scope import require_scope, roles_required

@app.get("/admin")
async def admin_dashboard(user=Depends(require_scope(["admin:read"]))):
    ...
```

---

## Utilization Example

### Dependency for OAuth Scope
```python
from fastapi import Depends
from app.core.db_utils.security.oauth_scope import require_scope

@app.get("/protected")
async def protected(user=Depends(require_scope(["user:read"]))):
    ...
```

### Dependency for Role-Based Access
```python
from fastapi import Depends
from app.core.db_utils.security.oauth_scope import roles_required

@app.post("/admin-action")
async def admin_action(roles=Depends(roles_required(["admin"]))):
    ...
```
- Document all available scopes and their intended use.
