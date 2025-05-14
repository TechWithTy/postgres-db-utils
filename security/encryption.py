import functools
from typing import Any, Callable, Awaitable
from app.core.db_utils.encryption import DataEncryptor
from app.core.db_utils.exceptions.exceptions import DatabaseError
from app.core.config import settings

# ! Decorator: Encrypt incoming sensitive kwargs only
def encrypt_incoming(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """
    Encrypts sensitive incoming kwargs (e.g., for DB queries).
    Only applies encryption to keys in settings.SENSITIVE_FIELDS.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        try:
            encrypted_kwargs = {
                k: DataEncryptor().encrypt(v) if k in settings.SENSITIVE_FIELDS else v
                for k, v in kwargs.items()
            }
        except Exception as e:
            raise DatabaseError(f"Failed to encrypt parameters: {e}") from e
        return await func(*args, **encrypted_kwargs)
    return wrapper

# ! Decorator: Decrypt outgoing sensitive fields only
def decrypt_outgoing(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    """
    Decrypts sensitive fields in the returned dict (e.g., for DB responses).
    Only applies decryption to keys in settings.SENSITIVE_FIELDS.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        result = await func(*args, **kwargs)
        if isinstance(result, dict):
            try:
                return {
                    k: DataEncryptor().decrypt(v) if k in settings.SENSITIVE_FIELDS else v
                    for k, v in result.items()
                }
            except Exception as e:
                raise DatabaseError(f"Failed to decrypt result: {e}") from e
        return result
    return wrapper
