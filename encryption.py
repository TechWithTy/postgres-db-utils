"""
Data encryption utilities with production-grade security features.
"""

import base64
import logging
import threading
import time
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from prometheus_client import Counter, Gauge

from app.core.config import settings
from app.core.db_utils.exceptions.exceptions import EncryptionError

logger = logging.getLogger(__name__)

# Prometheus metrics
ENCRYPTION_COUNTER = Counter(
    'data_encryption_operations_total',
    'Total encryption operations',
    ['operation', 'status']
)
ENCRYPTION_LATENCY = Gauge(
    'data_encryption_latency_seconds',
    'Encryption/decryption latency',
    ['operation']
)
KEY_ROTATION_COUNTER = Counter(
    'data_encryption_key_rotations_total',
    'Total key rotations performed'
)


class DataEncryptor:
    _instance = None
    _lock = threading.Lock()
    _cache_lock = threading.Lock()
    _rate_limit_lock = threading.Lock()
    _last_operation_time = 0
    _operation_count = 0

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Initialize the encryptor with validated key and cache."""
        self._validate_key_strength(settings.security.ENCRYPTION_KEY)
        self.cipher = Fernet(settings.security.ENCRYPTION_KEY)
        self._cache: dict[str, str] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def _validate_key_strength(self, key: str):
        """Validate that the encryption key is a valid Fernet key."""
        try:
            Fernet(key)
        except Exception as e:
            raise ValueError("Invalid ENCRYPTION_KEY for Fernet") from e
        self._last_key_rotation_check = time.time()
        self._key_version = 1  # Track key versions for rotation
        self._rate_limit_window = 60  # seconds
        self._rate_limit_max = settings.security.ENCRYPTION_RATE_LIMIT_MAX  # operations per window

    def _check_and_rotate_key(self):
        """Check if key rotation is needed and perform rotation."""
        current_time = time.time()
        if current_time - self._last_key_rotation_check > settings.security.ENCRYPTION_KEY_ROTATION_INTERVAL:
            with self._lock:
                if current_time - self._last_key_rotation_check > settings.security.ENCRYPTION_KEY_ROTATION_INTERVAL:
                    self._rotate_key()
                    self._last_key_rotation_check = current_time

    def _rotate_key(self):
        """Rotate to a new encryption key and invalidate cache."""
        logger.info("Initiating encryption key rotation")
        new_key = Fernet.generate_key()
        
        with self._cache_lock:
            self._cache.clear()
            
        self.cipher = Fernet(new_key)
        self._key_version += 1
        KEY_ROTATION_COUNTER.inc()
        logger.info(f"Key rotated to version {self._key_version}")

    def _check_rate_limit(self):
        """Enforce rate limiting on encryption operations."""
        current_time = time.time()
        with self._rate_limit_lock:
            if current_time - self._last_operation_time > self._rate_limit_window:
                self._operation_count = 0
                self._last_operation_time = current_time
            
            self._operation_count += 1
            if self._operation_count > self._rate_limit_max:
                raise EncryptionError("Rate limit exceeded for encryption operations")

    def encrypt(self, data: str) -> str:
        """Encrypt data with caching and rate limiting."""
        self._check_rate_limit()
        self._check_and_rotate_key()
        
        cache_key = f"enc_v{self._key_version}_{hash(data)}"

        with self._cache_lock:
            if cache_key in self._cache:
                self._cache_hits += 1
                ENCRYPTION_COUNTER.labels(operation='encrypt', status='cache_hit').inc()
                return self._cache[cache_key]
            self._cache_misses += 1

        try:
            start_time = time.monotonic()
            encrypted = self.cipher.encrypt(data.encode()).decode()
            duration = time.monotonic() - start_time
            ENCRYPTION_LATENCY.labels(operation='encrypt').set(duration)
            ENCRYPTION_COUNTER.labels(operation='encrypt', status='success').inc()

            if duration > 0.1:  # Log slow encryptions
                logger.warning(f"Slow encryption: {duration:.3f}s")

            with self._cache_lock:
                if len(self._cache) < settings.security.ENCRYPTION_CACHE_SIZE:
                    self._cache[cache_key] = encrypted

            return encrypted
        except Exception as e:
            ENCRYPTION_COUNTER.labels(operation='encrypt', status='error').inc()
            logger.error("Encryption failed", exc_info=True)
            # EncryptionError does not accept 'cause'; only pass message
            raise EncryptionError(f"Encryption failed: {str(e)}") from e

    def decrypt(self, token: str, key_version: int | None) -> str:
        """Decrypt data with cache lookup and version support."""
        self._check_rate_limit()
        
        if key_version is None:
            key_version = self._key_version
            
        cache_key = f"dec_v{key_version}_{hash(token)}"

        with self._cache_lock:
            if cache_key in self._cache:
                self._cache_hits += 1
                ENCRYPTION_COUNTER.labels(operation='decrypt', status='cache_hit').inc()
                return self._cache[cache_key]
            self._cache_misses += 1

        try:
            start_time = time.monotonic()
            decrypted = self.cipher.decrypt(token.encode()).decode()
            duration = time.monotonic() - start_time
            ENCRYPTION_LATENCY.labels(operation='decrypt').set(duration)
            ENCRYPTION_COUNTER.labels(operation='decrypt', status='success').inc()

            if duration > 0.1:  # Log slow decryptions
                logger.warning(f"Slow decryption: {duration:.3f}s")

            with self._cache_lock:
                if len(self._cache) < settings.security.ENCRYPTION_CACHE_SIZE:
                    self._cache[cache_key] = decrypted

            return decrypted
        except InvalidToken as e:
            ENCRYPTION_COUNTER.labels(operation='decrypt', status='invalid_token').inc()
            logger.error("Decryption failed - invalid token", exc_info=True)
            # EncryptionError does not accept 'cause'; only pass message
            raise EncryptionError("Invalid encryption token") from e
        except Exception as e:
            ENCRYPTION_COUNTER.labels(operation='decrypt', status='error').inc()
            logger.error("Decryption failed", exc_info=True)
            # EncryptionError does not accept 'cause'; only pass message
            raise EncryptionError(f"Decryption failed: {str(e)}") from e

    def get_cache_metrics(self) -> dict[str, Any]:
        """Get cache performance metrics."""
        with self._cache_lock:
            return {
                "size": len(self._cache),
                "hits": self._cache_hits,
                "misses": self._cache_misses,
                "hit_rate": (self._cache_hits / (self._cache_hits + self._cache_misses)
                           if (self._cache_hits + self._cache_misses) > 0 else 0),
                "key_version": self._key_version
            }
