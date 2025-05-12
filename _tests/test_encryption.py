"""
Production-ready tests for encryption.py
"""
import pytest
from unittest.mock import patch, MagicMock
from cryptography.fernet import InvalidToken, Fernet
from prometheus_client import CollectorRegistry
import time

from app.core.db_utils.encryption import DataEncryptor, EncryptionError

# ! Patch Fernet and settings for every test for isolation
def patch_settings_and_fernet(monkeypatch):
    valid_key = Fernet.generate_key().decode()
    mock_settings = MagicMock()
    mock_settings.ENCRYPTION_KEY = valid_key
    monkeypatch.setattr('app.core.config.settings', mock_settings)
    patcher_fernet = patch('cryptography.fernet.Fernet')
    mock_fernet = patcher_fernet.start()
    return mock_settings, mock_fernet, patcher_fernet

@pytest.mark.asyncio
class TestDataEncryptor:
    """Test suite for DataEncryptor class (production-ready, isolated, and robust)."""

    @pytest.fixture(autouse=True)
    def _setup(self, monkeypatch):
        # Patch settings and Fernet for every test
        # Patch Fernet where DataEncryptor uses it
        valid_key = Fernet.generate_key().decode()
        from app.core.config import settings
        settings.ENCRYPTION_KEY = valid_key
        settings.ENCRYPTION_KEY_ROTATION_INTERVAL = 0.1
        settings.ENCRYPTION_RATE_LIMIT_MAX = 10
        settings.ENCRYPTION_RATE_LIMIT_WINDOW = 1
        settings.ENCRYPTION_CACHE_SIZE = 100
        from app.core.db_utils.encryption import DataEncryptor
        DataEncryptor._instance = None
        patcher_fernet = patch('app.core.db_utils.encryption.Fernet')
        self.mock_fernet = patcher_fernet.start()
        yield
        patcher_fernet.stop()

    async def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption and decryption work correctly (mocked Fernet)."""
        encryptor = DataEncryptor()
        test_data = "sensitive data"
        # Make encrypted value different from plaintext
        self.mock_fernet.return_value.encrypt.return_value = b"encrypted-value"
        self.mock_fernet.return_value.decrypt.return_value = test_data.encode()
        encrypted = encryptor.encrypt(test_data)
        decrypted = encryptor.decrypt(encrypted, key_version=encryptor._key_version)
        assert decrypted == test_data
        assert encrypted != test_data

    async def test_encrypt_empty_string(self):
        """Test encryption with empty string (mocked Fernet)."""
        encryptor = DataEncryptor()
        self.mock_fernet.return_value.encrypt.return_value = b""
        self.mock_fernet.return_value.decrypt.return_value = b""
        encrypted = encryptor.encrypt("")
        decrypted = encryptor.decrypt(encrypted, key_version=encryptor._key_version)
        assert decrypted == ""

    async def test_decrypt_invalid_token(self):
        """Test decryption with invalid token (should raise InvalidToken)."""
        encryptor = DataEncryptor()
        self.mock_fernet.return_value.decrypt.side_effect = InvalidToken("Invalid token")
        with pytest.raises(EncryptionError):
            encryptor.decrypt("invalid_token", key_version=encryptor._key_version)


def test_key_rotation(monkeypatch):
    """Test that keys rotate after the configured interval."""
    import importlib
    import time
    from app.core.config import settings
    monkeypatch.setattr(settings.security, "ENCRYPTION_KEY_ROTATION_INTERVAL", 0.1)
    print(f"[test_key_rotation] Patched ENCRYPTION_KEY_ROTATION_INTERVAL: {settings.security.ENCRYPTION_KEY_ROTATION_INTERVAL}")
    enc_mod = importlib.import_module('app.core.db_utils.encryption')
    importlib.reload(enc_mod)
    DataEncryptor = enc_mod.DataEncryptor
    DataEncryptor._instance = None
    encryptor = DataEncryptor()
    original_key_version = encryptor.get_cache_metrics()["key_version"]
    encryptor.encrypt("test-init")
    encryptor._last_key_rotation_check = time.time() - 10
    print(f"[test_key_rotation] Forced last_key_rotation_check to {encryptor._last_key_rotation_check}")
    encryptor.encrypt("test")
    print(f"[test_key_rotation] After forced rotation, key_version: {encryptor.get_cache_metrics()['key_version']}, time: {time.monotonic()}")
    assert encryptor.get_cache_metrics()["key_version"] == original_key_version + 1


def test_cache_invalidation_after_rotation(monkeypatch):
    """Test that cache is cleared after key rotation."""
    import importlib
    import time
    from app.core.config import settings
    monkeypatch.setattr(settings.security, "ENCRYPTION_KEY_ROTATION_INTERVAL", 0.1)
    print(f"[test_cache_invalidation_after_rotation] Patched ENCRYPTION_KEY_ROTATION_INTERVAL: {settings.security.ENCRYPTION_KEY_ROTATION_INTERVAL}")
    enc_mod = importlib.import_module('app.core.db_utils.encryption')
    importlib.reload(enc_mod)
    DataEncryptor = enc_mod.DataEncryptor
    DataEncryptor._instance = None
    encryptor = DataEncryptor()
    encryptor.encrypt("test1")
    encryptor.encrypt("test2")
    assert encryptor.get_cache_metrics()["size"] > 0
    encryptor.encrypt("test-init")
    print(f"[test_cache_invalidation_after_rotation] After encrypt test-init: cache size={encryptor.get_cache_metrics()['size']}, key_version={encryptor.get_cache_metrics()['key_version']}, t={time.monotonic()}")
    encryptor._last_key_rotation_check = time.time() - 10
    print(f"[test_cache_invalidation_after_rotation] Forced last_key_rotation_check to {encryptor._last_key_rotation_check}")
    # This encrypt triggers rotation and should clear cache
    encryptor.encrypt("test3")
    print(f"[test_cache_invalidation_after_rotation] After encrypt test3: cache size={encryptor.get_cache_metrics()['size']}, key_version={encryptor.get_cache_metrics()['key_version']}, t={time.monotonic()}")
    # Assert cache has one entry immediately after rotation (the just-encrypted value)
    assert encryptor.get_cache_metrics()["size"] == 1
    # Subsequent encrypts will re-populate cache
    encryptor.encrypt("test4")
    print(f"[test_cache_invalidation_after_rotation] After encrypt test4: cache size={encryptor.get_cache_metrics()['size']}, key_version={encryptor.get_cache_metrics()['key_version']}, t={time.monotonic()}")


def test_rate_limiting(monkeypatch):
    """Test that rate limiting prevents excessive operations."""
    import importlib
    import time
    from app.core.config import settings
    monkeypatch.setattr(settings.security, "ENCRYPTION_RATE_LIMIT_MAX", 10)
    monkeypatch.setattr(settings.security, "ENCRYPTION_RATE_LIMIT_WINDOW", 1)
    print(f"[test_rate_limiting] Patched ENCRYPTION_RATE_LIMIT_MAX: {settings.security.ENCRYPTION_RATE_LIMIT_MAX}")
    print(f"[test_rate_limiting] Patched ENCRYPTION_RATE_LIMIT_WINDOW: {settings.security.ENCRYPTION_RATE_LIMIT_WINDOW}")
    enc_mod = importlib.import_module('app.core.db_utils.encryption')
    importlib.reload(enc_mod)
    DataEncryptor = enc_mod.DataEncryptor
    DataEncryptor._instance = None
    encryptor = DataEncryptor()
    encryptor._last_operation_time = time.time()
    encryptor._operation_count = 0
    print(f"[test_rate_limiting] Forced _last_operation_time to {encryptor._last_operation_time}, _operation_count to 0")
    print(f"[test_rate_limiting] Starting at time: {time.monotonic()}")
    num_encrypts = 0
    def try_encrypt():
        nonlocal num_encrypts
        try:
            encryptor.encrypt("test-exceed")
            num_encrypts += 1
            print(f"[test_rate_limiting] Encrypt {num_encrypts} succeeded at t={time.monotonic()}")
        except Exception as e:
            print(f"[test_rate_limiting] Encrypt {num_encrypts + 1} failed at t={time.monotonic()} with {type(e)}: {e}")
            raise
    with pytest.raises(EncryptionError, match="Rate limit exceeded"):
        for _ in range(11):
            try_encrypt()


def test_metrics_export():
    """Test that metrics are properly exported."""
    # Ensure real Fernet is used, not the mock
    from unittest.mock import patch
    patch.stopall()  # Remove all active patches/mocks
    from app.core.db_utils.encryption import DataEncryptor
    DataEncryptor._instance = None  # Reset singleton for clean state
    encryptor = DataEncryptor()

    # Perform operations
    encryptor.encrypt("test1")
    token = encryptor.encrypt("test2")
    version = encryptor.get_cache_metrics()["key_version"]
    encryptor.decrypt(token, key_version=version)
    
    metrics = encryptor.get_cache_metrics()
    assert "hits" in metrics
    assert "misses" in metrics
    assert "size" in metrics
    assert "key_version" in metrics
    
    # Verify Prometheus metrics are updated (would need integration tests for full verification)
