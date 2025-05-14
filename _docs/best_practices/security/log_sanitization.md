# Log Sanitization Best Practices

- Redact sensitive fields (passwords, tokens, PII) from all logs by default.
- Use a secure logger utility that enforces redaction and structured logging.
- Never log secrets or user data in plaintext.
- Log security-relevant events (auth failures, admin actions, rate limits) for audit.
- Regularly review logs for compliance and anomalies.

---

## Quick Start: Installation

```bash
pip install structlog
```

---

## Example: FastAPI Entrypoint

```python
import structlog
logger = structlog.get_logger()
logger.info("user_login", user_id=user.id, email=user.email)
```

---

## Utilization Example

### Log Sanitization Utility
```python
from app.core.db_utils.security.log_sanitization import log_endpoint_event

@log_endpoint_event("user_login")
def login_handler(...):
    ...
```
```

---

## Utilization Example

### Log Sanitization Utility
```python
from app.core.db_utils.security.log_sanitization import log_endpoint_event

@log_endpoint_event("user_login")
def login_handler(...):
    ...
