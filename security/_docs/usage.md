# Security Module Usage Guide

This guide explains how to use the security utilities provided in `security.py` for authentication, password management, and rate limiting in the Lead Ignite backend.

---

## Overview
The security module provides:
- JWT-based access token creation with encryption
- Password hashing and verification using a unified encryptor
- Rate limiting for token creation and password attempts (Redis-backed)

---

## Quick Start

### Token Creation
```python
from datetime import timedelta
from app.core.security.security import create_access_token

token = create_access_token(
    subject="user_id_or_email",
    expires_delta=timedelta(minutes=30)
)
```

### Password Hashing
```python
from app.core.security.security import get_password_hash

hashed = get_password_hash("my_password")
```

### Password Verification (with Rate Limit)
```python
from app.core.security.security import verify_password

try:
    valid = verify_password(
        plain_password="my_password",
        encrypted_hash=hashed,
        identifier="user_id_or_email"
    )
except HTTPException as e:
    # Handle rate limit exceeded
    ...
```

---

## Configuration
- `settings.SECRET_KEY`: Used for JWT signing (set in your environment/config).
- Redis must be running for rate limiting to work.
- Token and password attempt rate limits are set in `security.py`:
  - `TOKEN_CREATION_LIMIT = 30` (per minute)
  - `PASSWORD_ATTEMPT_LIMIT = 10` (per minute)

---

## Best Practices
- Always use `get_password_hash` for storing user passwords.
- Use `verify_password` to check passwords, which automatically rate limits attempts.
- Use `create_access_token` for issuing JWTs; this is also rate limited to prevent abuse.
- Handle `HTTPException` for rate limit errors in your API endpoints.
- Store `SECRET_KEY` securely and rotate periodically.
- Tune rate limits for your threat model and user base.

---

## Extending
- Integrate with 2FA or OAuth by extending token payloads.
- Adjust rate limits for higher/lower security requirements.
- Use `DataEncryptor` for other sensitive data encryption needs.

---

For implementation details, see the source code in `security.py` and additional docs in this directory.
