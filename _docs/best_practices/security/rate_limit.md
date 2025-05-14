# Rate Limiting Best Practices

- Apply rate limits to all sensitive and public endpoints.
- Use Valkey/Redis for distributed rate limiting and sliding window counters.
- Return HTTP 429 with `Retry-After` headers on limit breaches.
- Monitor and alert on rate limit breaches and potential abuse.
- Allow configurable limits per endpoint/user type.

---

## Example: FastAPI Entrypoint

```python
from fastapi import Depends
from app.core.db_utils.security.rate_limit import enforce_rate_limit

@app.post("/send-email")
async def send_email(rate_limited=Depends(enforce_rate_limit)):
    ...
```

---

## Utilization Example

### Dependency for Rate Limiting
```python
from fastapi import Depends
from app.core.db_utils.security.rate_limit import enforce_rate_limit

@app.post("/sensitive-action")
async def sensitive_action(rate_limited=Depends(enforce_rate_limit)):
    ...
