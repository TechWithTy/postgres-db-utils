# Input Validation Middleware Best Practices

This middleware validates and sanitizes all incoming requests for security and integrity.

- Applies to all incoming JSON and form data.
- Rejects requests with invalid or malicious input.
- Logs and blocks suspicious activity.

---

## Quick Start: Installation

```bash
pip install starlette
```

---

## Example: FastAPI Entrypoint

```python
from fastapi import FastAPI
from app.core.db_utils.security.input_validation_middleware import InputValidationMiddleware

app = FastAPI()
app.add_middleware(InputValidationMiddleware)
```

---

## Utilization Example

### Add Middleware
```python
from app.core.db_utils.security.input_validation_middleware import InputValidationMiddleware
app.add_middleware(InputValidationMiddleware)
```
```

---

## Utilization Example

### Add Middleware
```python
from app.core.db_utils.security.input_validation_middleware import InputValidationMiddleware
app.add_middleware(InputValidationMiddleware)
```

- Apply strict input validation to all incoming requests (JSON, form, query params).
- Use Pydantic models or custom middleware to enforce data schemas.
- Reject and log malformed or malicious input before business logic executes.
- Sanitize input to prevent injection, XSS, and other attacks.
- Centralize input validation logic for maintainability.
- Add automated tests for common attack vectors and malformed payloads.
