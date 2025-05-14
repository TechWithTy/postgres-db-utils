# Brute-Force & Replay Protection Best Practices

- Lock out users/IPs after repeated failed login attempts (e.g., 5 tries, 5 min lockout).
- Use nonce-based replay protection for sensitive operations and webhooks.
- Track and audit lockouts and suspicious activity.

---

## Utilization Example

### Nonce-Based Replay Protection
```python
from app.core.db_utils.security.replay_protection import check_and_store_nonce

# In your FastAPI route or webhook handler:
async def process_webhook(payload: dict):
    nonce = payload["nonce"]
    await check_and_store_nonce(nonce)
    # ...continue processing
```

### Brute-Force Lockout (see brute_force_and_token_revocation.md for full pattern)
- Use `record_failed_login`, `check_brute_force`, and `reset_failed_login` utilities for async brute-force protection.
