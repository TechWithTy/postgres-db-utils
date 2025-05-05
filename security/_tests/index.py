from datetime import timedelta
from unittest.mock import Mock

import pytest

from app.core.config import settings
from app.core.db_utils.encryption import DataEncryptor


@pytest.fixture
def mock_encryptor():
    """Fixture providing a mocked encryptor instance"""
    encryptor = Mock(spec=DataEncryptor)
    encryptor.encrypt.return_value = "encrypted_data"
    encryptor.decrypt.return_value = {"sub": "test_user"}
    encryptor.verify_hash.return_value = True
    encryptor.create_hash.return_value = "hashed_password"
    return encryptor


@pytest.fixture
def valid_token_payload():
    """Fixture providing standard valid token payload"""
    return {"sub": "test_user", "exp": timedelta(minutes=30)}


@pytest.fixture
def invalid_token_payload():
    """Fixture providing expired token payload"""
    return {
        "sub": "test_user",
        "exp": timedelta(microseconds=1),  # Immediately expires
    }
