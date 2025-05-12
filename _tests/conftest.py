"""
Shared test configuration for db_utils tests
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.core.config import settings
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

# Patch DB engine creation for integration tests to use SQLite in-memory DB and avoid SSL args
import pytest

@pytest.fixture(autouse=True)
def patch_db_engine(monkeypatch):
    import app.core.db_utils.db_config as db_config_mod
    def fake_get_db_url():
        # Use SQLite in-memory for safe, isolated tests
        return "sqlite+aiosqlite:///:memory:"
    monkeypatch.setattr(db_config_mod, "get_db_url", fake_get_db_url)

    def fake_create_engine():
        from sqlalchemy.ext.asyncio import create_async_engine
        pool_config = db_config_mod.get_pool_config()
        # Remove unsupported connect_args for SQLite
        return create_async_engine(
            fake_get_db_url(),
            pool_size=pool_config["pool_size"],
            max_overflow=pool_config["max_overflow"],
            pool_recycle=pool_config["pool_recycle"],
            pool_timeout=pool_config["pool_timeout"],
            pool_pre_ping=True,
            pool_use_lifo=True,
            echo=False,
        )
    monkeypatch.setattr(db_config_mod, "create_engine", fake_create_engine)
    yield

def _patched_metric_factory(factory, registry):
    def wrapper(*a, **kw):
        if 'registry' not in kw:
            kw['registry'] = registry
        return factory(*a, **kw)
    return wrapper

def pytest_configure(config):
    """
    Patch prometheus_client and prometheus_client.metrics globally for the entire test session,
    ensuring all metric definitions use a fresh test-local CollectorRegistry and patched metric classes.
    This prevents duplicated timeseries errors, even on module reloads or dynamic imports.
    """
    import sys
    from prometheus_client import CollectorRegistry
    import prometheus_client

    registry = CollectorRegistry()

    # Patch main prometheus_client module
    prometheus_client.REGISTRY = registry
    prometheus_client.Counter = _patched_metric_factory(prometheus_client.__dict__['Counter'], registry)
    prometheus_client.Gauge = _patched_metric_factory(prometheus_client.__dict__['Gauge'], registry)
    prometheus_client.Histogram = _patched_metric_factory(prometheus_client.__dict__['Histogram'], registry)

    # Patch sys.modules for all import paths
    sys.modules['prometheus_client'].REGISTRY = registry
    sys.modules['prometheus_client'].Counter = prometheus_client.Counter
    sys.modules['prometheus_client'].Gauge = prometheus_client.Gauge
    sys.modules['prometheus_client'].Histogram = prometheus_client.Histogram

    # Patch prometheus_client.metrics if present
    if hasattr(prometheus_client, "metrics") and "prometheus_client.metrics" in sys.modules:
        sys.modules["prometheus_client.metrics"].Counter = prometheus_client.Counter
        sys.modules["prometheus_client.metrics"].Gauge = prometheus_client.Gauge
        sys.modules["prometheus_client.metrics"].Histogram = prometheus_client.Histogram

    # Remove all existing collectors from the registry (start clean)
    collectors = list(getattr(registry, '_collector_to_names', {}).keys())
    for collector in collectors:
        try:
            registry.unregister(collector)
        except KeyError:
            pass

    # Configure pytest-asyncio
    import asyncio
    # Removed problematic _loop_factory override (caused RecursionError with pytest-asyncio)

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

class MockSecuritySettings:
    ENCRYPTION_KEY = "test_encryption_key_1234567890123456=="
    ENCRYPTION_ALGORITHM = "Fernet"
    ENCRYPTION_CACHE_SIZE = 100
    ENCRYPTION_KEY_ROTATION_INTERVAL = 0.1
    ENCRYPTION_RATE_LIMIT_WINDOW = 1
    ENCRYPTION_RATE_LIMIT_MAX = 10
    SECRET_KEY = "test_secret_key"

@pytest.fixture(autouse=True)
def patch_settings(monkeypatch):
    mock_settings = MagicMock()
    mock_settings.database = MockDatabaseSettings()
    mock_settings.security = MockSecuritySettings()
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
    sys.modules["app.core.config.settings"] = mock_settings  # Patch alternate import path
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
