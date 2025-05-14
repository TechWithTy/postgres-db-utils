# Replay Protection Best Practices

- Use nonce or timestamp-based mechanisms to prevent replay attacks.
- Validate uniqueness of requests for sensitive operations and webhooks.
- Expire nonces/tokens after a short window (e.g., 5 min).
- Log and alert on detected replay attempts.
- Test replay protection as part of security reviews.
