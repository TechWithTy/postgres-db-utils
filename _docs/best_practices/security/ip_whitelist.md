# IP Whitelisting Best Practices

- Restrict access to sensitive endpoints by IP address.
- Use a dynamic allow-list from environment/config.
- Log all denied/allowed requests for audit.

---

## Example: FastAPI Entrypoint

```python
from fastapi import Depends
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted

@app.get("/secure-data")
async def secure_data(ip_ok=Depends(verify_ip_whitelisted)):
    ...
```

---

## Utilization Example

### Dependency for IP Whitelisting
```python
from fastapi import Depends
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted

@app.post("/admin-action")
async def admin_action(ip_ok=Depends(verify_ip_whitelisted)):
    ...
```

- Provide clear error messages for denied requests (HTTP 403).
- Regularly audit and update the whitelist for compliance.
