# Security Best Practices for Lead Ignite Backend

This guide consolidates best practices from all security modules in `app.core.db_utils.security` and related files. Use these guidelines to ensure robust, compliant, and production-grade security for your FastAPI backend.

---

## 1. Authentication & Token Management
- Use strong, rotating `SECRET_KEY` values for JWT signing and encryption.
- Set short-lived token expirations (default: 30m) and implement refresh token rotation.
- Store tokens in HttpOnly cookies when possible.
- Always validate and verify JWTs and API keys using a trusted backend service (e.g., SupabaseAuthService).
- Revoke tokens on logout or suspicious activity using Redis-backed revocation lists.

## 2. Password & Credential Security
- Enforce a minimum password length (12+ chars) and reject common passwords.
- Use strong password hashing and encryption (e.g., DataEncryptor).
- Rate limit password attempts (e.g., 10/min per user) to prevent brute-force attacks.
- Never log or expose plaintext passwords or secrets.

## 3. Rate Limiting & Abuse Protection
- Apply Redis-backed rate limits to all sensitive endpoints (login, token creation, API calls).
- Use sliding window counters for precise rate enforcement.
- Return HTTP 429 with `Retry-After` headers on limit breaches.
- Monitor and alert on rate limit breaches and failed auth attempts.

## 4. Brute-Force & Replay Protection
- Lock out users/IPs after repeated failed login attempts (e.g., 5 tries, 5 min lockout).
- Use nonce-based replay protection for sensitive operations and webhooks.
- Track and audit lockouts and suspicious activity.

## 5. Multi-Factor Authentication (MFA)
- Integrate TOTP and backup codes for user accounts.
- Rate limit MFA attempts and lock out after repeated failures.
- Log all MFA-related events for audit trails.

## 6. Input Validation & Sanitization
- Apply input validation middleware to all incoming JSON/form data.
- Block and log requests with malicious or malformed input.
- Sanitize data to prevent injection and XSS attacks.

## 7. IP Whitelisting & Network Controls
- Enforce IP whitelisting for admin or sensitive endpoints.
- Use environment-configurable, dynamically reloadable whitelists.
- Log all whitelist denials and suspicious access.

## 8. Secure Logging & Audit Trails
- Use a logger that redacts sensitive fields (passwords, tokens, PII) by default.
- Never print secrets or user data to logs.
- Log all security-relevant events (auth, rate limits, admin actions) for compliance.

## 9. Webhook Security
- Validate webhook signatures using HMAC and a secret from environment variables.
- Reject unsigned or invalid webhooks with HTTP 401/403.
- Never process webhooks without verifying authenticity.

## 10. OAuth & Scope Management
- Always check and enforce OAuth scopes for each endpoint.
- Use dependency helpers to validate user permissions and scopes.

## 11. Exception Handling
- Use centralized exception handling for all HTTP and business logic errors.
- Log and raise exceptions with enough detail for auditing, but never expose sensitive info in responses.

---

## Implementation Snippets

- **Password Verification with Rate Limit:**
```python
from app.core.db_utils.security.security import verify_password
try:
    valid = verify_password(plain_password, encrypted_hash, identifier)
except HTTPException as e:
    # Handle rate limit exceeded
    ...
```

- **Brute-Force Lockout Check:**
```python
from app.core.db_utils.security.brute_force_and_token_revocation import check_brute_force
await check_brute_force(email, ip)
```

- **Webhook Signature Validation:**
```python
from app.core.db_utils.security.webhooks import verify_webhook_signature
is_valid = await verify_webhook_signature(request)
```

- **Input Validation Middleware:**
```python
from app.core.db_utils.security.input_validation_middleware import InputValidationMiddleware
app.add_middleware(InputValidationMiddleware)
```

- **IP Whitelist Dependency:**
```python
from app.core.db_utils.security.ip_whitelist import verify_ip_whitelisted
ip_whitelisted = Depends(verify_ip_whitelisted)
```

- **Log Sanitization:**
```python
from app.core.db_utils.security.log_sanitization import get_secure_logger
logger = get_secure_logger("my.module")
```

---

## Checklist
- [ ] Rotate `SECRET_KEY` and encryption keys regularly
- [ ] Configure and monitor all rate limits
- [ ] Enable MFA for all privileged accounts
- [ ] Validate and sanitize all inputs
- [ ] Enforce IP whitelisting where appropriate
- [ ] Redact logs and audit all security events
- [ ] Document all exceptions and error responses

---

*Last updated: 2025-05-13*
