"""
Production-ready tests for encryption.py
"""
import pytest
from unittest.mock import patch, MagicMock
from cryptography.fernet import InvalidToken, Fernet
import time

from app.core.db_utils.encryption import DataEncryptor, EncryptionError


@pytest.mark.asyncio
class TestDataEncryptor:
    """Test suite for DataEncryptor class"""

    @pytest.fixture(autouse=True)
    def _setup_mocks(self, mock_fernet):
        """Setup common mocks for all tests"""
        # Generate a valid Fernet key for testing
        valid_key = Fernet.generate_key().decode()
        self.mock_settings = MagicMock()
        self.mock_settings.ENCRYPTION_KEY = valid_key
        self.patcher = patch('app.core.config.settings', self.mock_settings)
        self.patcher.start()
        yield
        self.patcher.stop()

    async def test_encrypt_decrypt_roundtrip(self, mock_fernet):
        """Test that encryption and decryption work correctly"""
        encryptor = DataEncryptor()
        test_data = "sensitive data"
        
        # Setup mock Fernet behavior
        mock_fernet.encrypt.return_value = test_data.encode()
        mock_fernet.decrypt.return_value = test_data.encode()
        
        # Encrypt and decrypt
        encrypted = encryptor.encrypt(test_data)
        decrypted = encryptor.decrypt(encrypted)
        
        assert decrypted == test_data
        assert encrypted != test_data

    async def test_encrypt_empty_string(self, mock_fernet):
        """Test encryption with empty string"""
        encryptor = DataEncryptor()
        mock_fernet.encrypt.return_value = b""
        mock_fernet.decrypt.return_value = b""
        
        encrypted = encryptor.encrypt("")
        decrypted = encryptor.decrypt(encrypted)
        
        assert decrypted == ""

    async def test_decrypt_invalid_token(self, mock_fernet):
        """Test decryption with invalid token"""
        encryptor = DataEncryptor()
        mock_fernet.decrypt.side_effect = InvalidToken("Invalid token")
        
        with pytest.raises(InvalidToken):
            encryptor.decrypt("invalid_token")


def test_key_rotation(monkeypatch):
    """Test that keys rotate after the configured interval."""
    # Set a very short rotation interval for testing
    monkeypatch.setattr("app.core.config.ENCRYPTION_KEY_ROTATION_INTERVAL", 0.1)
    
    encryptor = DataEncryptor()
    original_key_version = encryptor.get_cache_metrics()["key_version"]
    
    # Wait for rotation interval to pass
    import time
    time.sleep(0.2)
    
    # Trigger rotation check
    encryptor.encrypt("test")
    
    assert encryptor.get_cache_metrics()["key_version"] == original_key_version + 1


def test_cache_invalidation_after_rotation(monkeypatch):
    """Test that cache is cleared after key rotation."""
    monkeypatch.setattr("app.core.config.ENCRYPTION_KEY_ROTATION_INTERVAL", 0.1)
    
    encryptor = DataEncryptor()
    encryptor.encrypt("test1")
    encryptor.encrypt("test2")
    
    # Verify cache is populated
    assert encryptor.get_cache_metrics()["size"] > 0
    
    # Wait for rotation
    import time
    time.sleep(0.2)
    encryptor.encrypt("test3")
    
    # Cache should be empty after rotation
    assert encryptor.get_cache_metrics()["size"] == 0


def test_rate_limiting():
    """Test that rate limiting prevents excessive operations."""
    encryptor = DataEncryptor()
    
    # Should work under limit
    for _ in range(10):
        encryptor.encrypt("test")
    
    # Should fail when exceeding limit
    monkeypatch.setattr("app.core.config.ENCRYPTION_RATE_LIMIT_MAX", 10)
    monkeypatch.setattr("app.core.config.ENCRYPTION_RATE_LIMIT_WINDOW", 1)
    
    with pytest.raises(EncryptionError, match="Rate limit exceeded"):
        for _ in range(11):
            encryptor.encrypt("test")


def test_metrics_export():
    """Test that metrics are properly exported."""
    encryptor = DataEncryptor()
    
    # Perform operations
    encryptor.encrypt("test1")
    encryptor.decrypt(encryptor.encrypt("test2"))
    
    metrics = encryptor.get_cache_metrics()
    assert "hits" in metrics
    assert "misses" in metrics
    assert "hit_rate" in metrics
    assert "key_version" in metrics
    
    # Verify Prometheus metrics are updated (would need integration tests for full verification)
