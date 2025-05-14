# Authentication & Token Management Best Practices

- Use strong, rotating `SECRET_KEY` values for JWT signing and encryption.
- Set short-lived token expirations (default: 30m) and implement refresh token rotation.
- Store tokens in HttpOnly cookies when possible.
- Always validate and verify JWTs and API keys using a trusted backend service (e.g., SupabaseAuthService).
- Revoke tokens on logout or suspicious activity using Redis-backed revocation lists.
