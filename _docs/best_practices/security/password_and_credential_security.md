# Password & Credential Security Best Practices

- Enforce a minimum password length (12+ chars) and reject common passwords.
- Use strong password hashing and encryption (e.g., DataEncryptor).
- Rate limit password attempts (e.g., 10/min per user) to prevent brute-force attacks.
- Never log or expose plaintext passwords or secrets.

---

## Example: Hashing and Verifying Passwords

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

hashed = pwd_context.hash("mysecretpassword")
assert pwd_context.verify("mysecretpassword", hashed)
```

---

## Utilization Example

### Password Hashing/Verification Utility
```python
from app.core.db_utils.security.security import hash_password, verify_password

hashed = hash_password("mysecretpassword")
assert verify_password("mysecretpassword", hashed)
