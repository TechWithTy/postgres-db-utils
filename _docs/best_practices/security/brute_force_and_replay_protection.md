# Brute-Force & Replay Protection Best Practices

- Lock out users/IPs after repeated failed login attempts (e.g., 5 tries, 5 min lockout).
- Use nonce-based replay protection for sensitive operations and webhooks.
- Track and audit lockouts and suspicious activity.
