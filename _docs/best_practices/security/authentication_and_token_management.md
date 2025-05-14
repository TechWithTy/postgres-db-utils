# Authentication & Token Management Best Practices

- Use strong, rotating `SECRET_KEY` values for JWT signing and encryption.
- Set short-lived token expirations (default: 30m) and implement refresh token rotation.
- Store tokens in HttpOnly cookies when possible.
- Always validate and verify JWTs and API keys using a trusted backend service (e.g., SupabaseAuthService).
- Revoke tokens on logout or suspicious activity using Redis-backed revocation lists.

---

## Utilization Example

### FastAPI Dependency
```python
from app.core.db_utils.security.authentication import authenticate_user
from fastapi import Depends

@app.get("/secure-data")
async def secure_data(user=Depends(authenticate_user)):
    # user is a dict with 'user' and 'auth_type'
    ...
```

### Admin User Lookup
```python
from app.core.db_utils.security.authentication import admin_lookup_user
user = await admin_lookup_user(user_id)
