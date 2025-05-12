"""
Shared test configuration for db_utils tests
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.core.config import settings
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

@pytest.fixture(autouse=True)
def patch_prometheus_registry(monkeypatch):
    """Patch Prometheus registry and metric classes to avoid duplicate registration in tests."""
    registry = CollectorRegistry()
    monkeypatch.setattr("prometheus_client.REGISTRY", registry)
    monkeypatch.setattr("prometheus_client.Counter", lambda *a, **kw: Counter(*a, registry=registry, **kw))
    monkeypatch.setattr("prometheus_client.Gauge", lambda *a, **kw: Gauge(*a, registry=registry, **kw))
    monkeypatch.setattr("prometheus_client.Histogram", lambda *a, **kw: Histogram(*a, registry=registry, **kw))

# Configure pytest-asyncio
def pytest_configure(config):
    config.option.asyncio_fixture_loop_scope = "function"

# * Robust fixture to patch settings.database for all tests
class MockDatabaseSettings:
    DB_USER = "test_user"
    DB_PASSWORD = "test_password"
    DB_NAME = "test_db"
    DB_HOST = "localhost"
    DB_PORT = 5432
    SUPABASE_DB_CONNECTION_DIRECT = "postgresql://mock:mock@localhost/mock"
    DATABASE_URL = "postgresql://test_user:test_password@localhost:5432/test_db"
    DB_POOL_SIZE = 5
    DB_MAX_OVERFLOW = 10
    DB_POOL_RECYCLE = 1800
    DB_POOL_TIMEOUT = 30
    SQL_ECHO = False
    FIRST_SUPERUSER = "admin@example.com"
    FIRST_SUPERUSER_PASSWORD = "testpass"
    ENV = "test"
    # Add any other attributes your code/tests need

import sys

@pytest.fixture(autouse=True)
def patch_settings(monkeypatch):
    mock_settings = MagicMock()
    mock_settings.database = MockDatabaseSettings()
    # Patch ENV and DATABASE_URL at the top level as well
    mock_settings.ENV = "test"
    mock_settings.DATABASE_URL = "postgresql://test_user:test_password@localhost:5432/test_db"
    # Patch database.DATABASE_URL at the top level for compatibility
    mock_settings.database.DATABASE_URL = "postgresql://test_user:test_password@localhost:5432/test_db"
    # Patch METRICS_PORT and METRICS_ENABLED as real values to avoid OSError
    mock_settings.METRICS_PORT = 9090
    mock_settings.METRICS_ENABLED = False
    # Patch sys.modules so all imports use the mock
    sys.modules["app.core.config"].settings = mock_settings
    monkeypatch.setattr('app.core.config.settings', mock_settings)
    return mock_settings

@pytest.fixture
def mock_env():
    """Fixture for patching environment variables if needed"""
    with patch.dict('os.environ', {"ENV": "test"}):
        yield

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
