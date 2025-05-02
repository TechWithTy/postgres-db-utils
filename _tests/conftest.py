"""
Shared test configuration for db_utils tests
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.core.config import settings

# Configure pytest-asyncio
def pytest_configure(config):
    config.option.asyncio_fixture_loop_scope = "function"

@pytest.fixture
def mock_db_pool():
    """Fixture providing complete mock database pool settings"""
    mock_settings = MagicMock()
    mock_settings.SUPABASE_DB_CONNECTION_DIRECT = "postgresql://mock:mock@localhost/mock"
    mock_settings.DATABASE_URL = "postgresql://mock:mock@localhost/mock"
    mock_settings.DB_POOL_SIZE = 5
    mock_settings.DB_MAX_OVERFLOW = 10
    mock_settings.DB_POOL_RECYCLE = 1800
    mock_settings.DB_POOL_TIMEOUT = 30
    mock_settings.SQL_ECHO = False
    return mock_settings

@pytest.fixture
def mock_db_engine():
    """Fixture providing mock database engine with URL"""
    engine = MagicMock()
    engine.url = settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
    return engine

@pytest.fixture
def mock_db_session():
    """Fixture providing a mock database session"""
    mock = AsyncMock()
    mock.commit = AsyncMock()
    mock.close = AsyncMock()
    return mock

@pytest.fixture
def mock_pool_module(mock_db_pool, mock_db_engine):
    """Fixture providing mocked pool module"""
    with patch('app.core.db_utils.pool._import_sqlalchemy'), \
         patch('app.core.db_utils.pool.create_async_engine', return_value=mock_db_engine), \
         patch('app.core.config.settings', mock_db_pool):
        yield

@pytest.fixture
def mock_fernet():
    """Fixture providing mock Fernet instance for encryption tests"""
    mock = MagicMock()
    mock.encrypt.side_effect = lambda x: x
    mock.decrypt.side_effect = lambda x: x
    return mock
