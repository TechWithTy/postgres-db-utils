# Rate Limiting & Abuse Protection Best Practices

- Apply Redis-backed rate limits to all sensitive endpoints (login, token creation, API calls).
- Use sliding window counters for precise rate enforcement.
- Return HTTP 429 with `Retry-After` headers on limit breaches.
- Monitor and alert on rate limit breaches and failed auth attempts.

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

### Dependency for Rate Limiting & Abuse Protection
```python
from fastapi import Depends
from app.core.db_utils.security.rate_limit import enforce_rate_limit

@app.post("/protected")
async def protected(rate_limited=Depends(enforce_rate_limit)):
    ...
```
