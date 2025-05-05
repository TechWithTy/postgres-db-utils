# Security Implementation Guide

## Architecture
- **JWT Tokens**: HS256 signed + encrypted payloads
- **Password Storage**: Encrypted + hashed via DataEncryptor
- **Rate Limiting**: Redis-backed sliding window counters

## Key Components
```python
from app.core.security import (
    create_access_token,  # Rate limited token creation
    verify_password,      # Brute-force protected
    get_password_hash     # Encryption + hashing
)
```

## Rate Limits
| Feature               | Limit      | Window |
|-----------------------|------------|--------|
| Token Creation        | 30 req     | 1 min  |
| Password Attempts     | 10 req     | 1 min  |
