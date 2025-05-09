"""
Database operation decorators integrated with core utilities.
"""

import asyncio
import functools
import logging
import time
from typing import Any, Callable, Optional, Type

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.core.config import settings
from app.core.db_utils.db_config import create_engine, get_db_url
from app.core.db_utils.db_optimizations import QueryOptimizer
from app.core.db_utils.encryption import DataEncryptor
from app.core.db_utils.pool import get_pool_metrics
from app.core.db_utils.sensitive import load_environment_files

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class DatabaseError(Exception):
    """Base exception for database operations"""

    def __init__(
        self,
        message: str,
        context: dict | None = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.context = context or {}
        self.__cause__ = cause
        logger.error(f"DatabaseError: {message}", extra={"context": context})


class ConnectionError(DatabaseError):
    """Exception for connection-related issues"""

    def __init__(
        self,
        message: str,
        connection_details: dict | None = None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message, {"connection": connection_details}, cause)


class EncryptionError(DatabaseError):
    """Exception for encryption-related issues"""

    def __init__(
        self,
        message: str,
        field: str | None,
        cause: Optional[Exception] = None,
    ):
        super().__init__(message, {"field": field}, cause)


class RetryableError(DatabaseError):
    """Exception for operations that can be retried"""

    pass


def retry_decorator(
    max_retries: int = 3, exceptions: Optional[tuple[Type[Exception], ...]] = None
):
    """
    Generic retry decorator for database operations.
    Args:
        max_retries: Maximum number of retry attempts
        exceptions: Tuple of exception types to retry on
    """
    exceptions = exceptions or (RetryableError, ConnectionError)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            for attempt in range(1, max_retries + 1):
                try:
                    logger.debug(f"Attempt {attempt} of {max_retries}")
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    logger.warning(
                        f"Attempt {attempt} failed: {str(e)}",
                        exc_info=True,
                        extra={"retry_attempt": attempt},
                    )
                    if attempt == max_retries:
                        raise
                    await asyncio.sleep(
                        min(2**attempt, 10)
                    )  # Exponential backoff with max 10s
            raise last_exception  # This line should never be reached

        return wrapper

    return decorator


def with_engine_connection(func: Callable) -> Callable:
    """
    Decorator that provides a managed database connection.
    Uses create_engine() from db_config.py
    """

    @functools.wraps(func)
    @retry_decorator(max_retries=settings.DB_CONNECTION_RETRIES)
    async def wrapper(*args, **kwargs) -> Any:
        start_time = time.monotonic()
        logger.debug("Creating database connection")

        try:
            engine = create_engine()
            async with engine.connect() as conn:
                logger.debug("Database connection established")
                result = await func(conn, *args, **kwargs)
                duration = time.monotonic() - start_time
                logger.debug(f"Operation completed in {duration:.2f}s")
                return result
        except Exception as e:
            duration = time.monotonic() - start_time
            logger.error(
                f"Database operation failed after {duration:.2f}s",
                exc_info=True,
                extra={"duration": duration},
            )
            raise ConnectionError(
                f"Failed to establish database connection: {str(e)}",
                {"retries": settings.DB_CONNECTION_RETRIES},
                e,
            ) from e

    return wrapper


def with_query_optimization(func: Callable) -> Callable:
    """
    Decorator that optimizes queries using QueryOptimizer.
    Integrates with db_optimizations.py
    """

    @functools.wraps(func)
    async def wrapper(model_class, *args, **kwargs) -> Any:
        optimizer = QueryOptimizer(model_class)
        query = kwargs.get("query")
        if query:
            kwargs["query"] = optimizer.optimize_queryset(query)
        return await func(model_class, *args, **kwargs)

    return wrapper


def with_pool_metrics(func: Callable) -> Callable:
    """
    Decorator that tracks pool metrics using ConnectionPoolMonitor.
    Integrates with pool.py
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        result = await func(*args, **kwargs)
        metrics = get_pool_metrics()
        logger.debug(f"Pool metrics after operation: {metrics}")
        return result

    return wrapper


def with_secure_environment(func: Callable) -> Callable:
    """
    Decorator that ensures environment is loaded securely.
    Uses load_environment_files() from sensitive.py
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        load_environment_files()
        return await func(*args, **kwargs)

    return wrapper


def with_encrypted_parameters(func: Callable) -> Callable:
    """
    Decorator that automatically encrypts/decrypts parameters.
    Uses encrypt_data/decrypt_data from encryption.py
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs) -> Any:
        # Encrypt sensitive kwargs before passing to function
        encrypted_kwargs = {
            k: DataEncryptor().encrypt(v) if k in settings.SENSITIVE_FIELDS else v
            for k, v in kwargs.items()
        }
        result = await func(*args, **encrypted_kwargs)

        # Decrypt sensitive results before returning
        if isinstance(result, dict):
            return {
                k: DataEncryptor().decrypt(v) if k in settings.SENSITIVE_FIELDS else v
                for k, v in result.items()
            }
        return result

    return wrapper
