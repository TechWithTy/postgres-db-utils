# Sensitive Data Usage Best Practices

- Always encrypt sensitive fields at rest and in transit.
- Use Fernet or equivalent for symmetric encryption.
- Never log or transmit unencrypted sensitive data.
- Rotate encryption keys regularly and securely.
- Store secrets and encryption keys in environment variables, never in code.

---

## Loading Environment Variables for Secure Key Management

```python
import sys
from pathlib import Path
from dotenv import load_dotenv

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Add the apps directory to the Python path
sys.path.insert(0, str(BASE_DIR / "apps"))

# Define path for the environment file
env_path = BASE_DIR.parent / ".env"

def load_environment_files():
    """Load environment variables from .env file if exists"""
    if env_path.exists():
        path_str = str(env_path)  # Use raw path string
        print(f"Loading environment file: {path_str}")
        load_dotenv(path_str, override=True)
    else:
        print("No .env file found. Using system environment variables.")
```

---

## Example: Encrypting/Decrypting Sensitive Fields

```python
from app.core.db_utils.encryption import DataEncryptor

encryptor = DataEncryptor()

ciphertext = encryptor.encrypt("my sensitive data")
decrypted = encryptor.decrypt(ciphertext)
```

---

## Utilization Example

### Field-Level Encryption Utility for FastAPI

```python
from app.core.db_utils.security.encryption import encrypt_incoming, decrypt_outgoing

@encrypt_incoming
@decrypt_outgoing
async def process_sensitive_data(...):
    ...
```

- Decorators ensure that only fields marked as sensitive are encrypted before storage and decrypted on retrieval.
- Use with Pydantic models to enforce field-level security.
