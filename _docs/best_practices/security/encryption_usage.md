# Encryption Utilities Usage Guide

This module provides secure, production-ready encryption utilities for **all sensitive data**—not just DB fields. Use these tools for API payloads, files, messages, logs, and more.

- Fernet symmetric encryption (cryptography)
- Automatic key validation and rotation
- In-memory cache for performance
- Prometheus metrics for observability
- Rate limiting for abuse prevention
- Structured logging and error handling

---

## Quickstart Example (All Data)

```python
from pydantic import BaseModel
from app.core.db_utils.encryption import DataEncryptor
from app.core.db_utils.security.encryption import encrypt_incoming
from fastapi import APIRouter

router = APIRouter()

encryptor = DataEncryptor()

# Direct encrypt/decrypt usage
plaintext = "my sensitive data"
ciphertext = encryptor.encrypt(plaintext)
print(f"Ciphertext: {ciphertext}")
decrypted = encryptor.decrypt(ciphertext)
print(f"Decrypted: {decrypted}")

# Example Pydantic model
class SensitivePayload(BaseModel):
    ssn: str
    credit_card: str
    note: str

# Example FastAPI endpoint using the decorator
def store_sensitive_data(ssn: str, credit_card: str, note: str):
    # At this point, sensitive fields are encrypted if decorated
    return {"status": "encrypted and stored"}

@router.post("/secure-data")
@encrypt_incoming
def secure_endpoint(ssn: str, credit_card: str, note: str):
    # All sensitive fields are encrypted by the decorator
    return {"status": "encrypted and stored"}

plaintext = encryptor.decrypt(ciphertext, key_version=None)  # Use None for current key
```

---

## Decorators for Automatic Encryption/Decryption

These decorators can be used for any API, DB, or background function—not just DB queries!

```python
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing

# Encrypt only incoming sensitive fields (e.g., before DB write, API ingest)
@encrypt_incoming
def store_sensitive_data(password: str, ...):
    ...

# Decrypt only outgoing sensitive fields (e.g., before API response, after DB fetch)
@decrypt_outgoing
def fetch_sensitive_data(...):
    ...
```

You can combine both for full round-trip protection:

```python
@decrypt_outgoing
@encrypt_incoming
def handle_sensitive(...):
    ...
```

---

## Best Practices
- Use `encrypt_incoming` for any handler that ingests or stores sensitive data.
- Use `decrypt_outgoing` for any handler that returns sensitive data to clients or external systems.
- Use config toggles (`enable_encryption_incoming`, `enable_encryption_exporting`) to control application per endpoint or service.
- Works for API payloads, DB records, files, logs, and more.
- Never log decrypted sensitive data.
- Rotate keys regularly and monitor Prometheus metrics for anomalies.

---

## Example: API Route with Encryption Decorators

```python
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing

@decrypt_outgoing
@encrypt_incoming
async def api_handler(password: str, ...):
    # password is encrypted before logic, decrypted before returning
    ...
```

---

**These utilities are for general-purpose encryption and decryption across your stack, not just for DB!**

```

---

## Key Features

- **Singleton Pattern:** Use `DataEncryptor()` anywhere, always returns the same instance.
- **Key Management:** Key is loaded from `settings.security.ENCRYPTION_KEY` (must be Fernet-compatible).
- **Key Rotation:** Automatic, interval-based rotation. Old cache is invalidated on rotation.
- **Caching:** Encrypt/decrypt operations are cached for speed (size set by `ENCRYPTION_CACHE_SIZE`).
- **Rate Limiting:** Max operations per window (`ENCRYPTION_RATE_LIMIT_MAX`), configurable in settings.
- **Metrics:** Prometheus counters/gauges for ops, latency, cache hits, and key rotations.

---

## Advanced Usage

### Customizing Settings

- Set environment variables or `settings.security` for:
  - `ENCRYPTION_KEY`
  - `ENCRYPTION_RATE_LIMIT_MAX`
  - `ENCRYPTION_KEY_ROTATION_INTERVAL`
  - `ENCRYPTION_CACHE_SIZE`

### Key Rotation

- Keys rotate automatically based on interval.
- To force rotation: call `encryptor._rotate_key()` (for admin/scripts only).

### Cache Metrics

---

## Advanced Usage Patterns

### 1. File Encryption/Decryption

Encrypt and decrypt files on disk or in cloud storage:

```python
from app.core.db_utils.encryption import DataEncryptor

def encrypt_file(input_path: str, output_path: str):
    encryptor = DataEncryptor()
    with open(input_path, "rb") as f:
        plaintext = f.read()
    ciphertext = encryptor.encrypt(plaintext.decode("utf-8"))
    with open(output_path, "wb") as f:
        f.write(ciphertext.encode("utf-8"))

def decrypt_file(input_path: str, output_path: str):
    encryptor = DataEncryptor()
    with open(input_path, "rb") as f:
        ciphertext = f.read()
    plaintext = encryptor.decrypt(ciphertext.decode("utf-8"))
    with open(output_path, "wb") as f:
        f.write(plaintext.encode("utf-8"))
```

---

### 2. Message Queue Encryption (Pulsar, Redis, Kafka, etc)

Encrypt messages before publishing and decrypt after consuming:

```python
from app.core.db_utils.encryption import DataEncryptor

def publish_encrypted_message(producer, message: dict):
    encryptor = DataEncryptor()
    encrypted_payload = encryptor.encrypt(json.dumps(message))
    producer.send(encrypted_payload)

def consume_and_decrypt_message(consumer):
    encryptor = DataEncryptor()
    encrypted_payload = consumer.receive()
    message = json.loads(encryptor.decrypt(encrypted_payload))
    return message
```

---

### 3. Integration with Other Security Layers

**a. Signing and Encryption**

```python
from app.core.db_utils.encryption import DataEncryptor
from app.core.db_utils.security.signing import sign_data, verify_signature

def secure_send(data: str, private_key):
    encryptor = DataEncryptor()
    ciphertext = encryptor.encrypt(data)
    signature = sign_data(ciphertext, private_key)
    return {"ciphertext": ciphertext, "signature": signature}

def secure_receive(ciphertext: str, signature: str, public_key):
    if not verify_signature(ciphertext, signature, public_key):
        raise ValueError("Signature invalid!")
    encryptor = DataEncryptor()
    return encryptor.decrypt(ciphertext)
```

**b. JWT and API Gateway**

- Encrypt sensitive JWT claims before issuing tokens.
- Decrypt claims after JWT verification in your backend.
- Use API gateway middleware to enforce encryption for sensitive headers or payloads.

---

## Best Practices Recap
- Use encryption for files, messages, API, DB, and inter-service communication.
- Combine with signing for authenticity.
- Always decrypt before using sensitive data in business logic.
- Integrate with your monitoring and alerting for auditability.

---


```python
metrics = encryptor.get_cache_metrics()
print(metrics)  # {'size': ..., 'hits': ..., 'misses': ..., 'hit_rate': ..., 'key_version': ...}
```

---

## Security & Best Practices

- **Never hardcode encryption keys.** Use environment variables.
- **Rotate keys regularly** (interval is configurable).
- **Monitor Prometheus metrics** for slow ops or errors.
- **Handle EncryptionError** in your code for robust error handling.
- **Do not expose decrypted data in logs or errors.**

---

## Troubleshooting

- `EncryptionError`: Check key validity, rate limits, and logs.
- `InvalidToken` on decrypt: Token or key mismatch (possible rotation or corruption).
- Cache issues: Metrics help diagnose hit/miss rate and cache size.

---

## Reference

- `DataEncryptor.encrypt(data: str) -> str`
- `DataEncryptor.decrypt(token: str, key_version: int | None) -> str`
- `DataEncryptor.get_cache_metrics() -> dict`
- Prometheus metrics: `data_encryption_operations_total`, `data_encryption_latency_seconds`, `data_encryption_key_rotations_total`

---

*Guide updated 2025-05-13. For advanced patterns, see inline code comments.*
