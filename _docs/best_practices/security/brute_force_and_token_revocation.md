# Brute Force and Token Revocation Best Practices

- Lock out users/IPs after repeated failed login attempts (e.g., 5 tries, 5 min lockout).
- Use Redis/Valkey to track failed attempts and implement lockouts.
- Revoke tokens on suspicious activity or logout using a revocation list.
- Ensure revocation checks are performed on every request requiring authentication.
- Log all lockout and revocation events for audit and compliance.
- Monitor for brute-force attack patterns and alert on anomalies.

---

## Utilization Example

### Brute-Force Protection
```python
from app.core.db_utils.security.brute_force_and_token_revocation import (
    check_brute_force, record_failed_login, reset_failed_login
)

# In your login route:
async def login(email: str, ip: str, password: str):
    await check_brute_force(email, ip)  # Check lockout before processing
    # ...authenticate user...
    if failed:
        await record_failed_login(email, ip)
    else:
        await reset_failed_login(email, ip)
```

### Token Revocation
```python
from app.core.db_utils.security.brute_force_and_token_revocation import (
    revoke_token, is_token_revoked
)

# To revoke a JWT (e.g., on logout or suspicious activity):
await revoke_token(jti, exp)

# To check if a JWT is revoked:
revoked = await is_token_revoked(jti)
if revoked:
    # deny access
    ...
