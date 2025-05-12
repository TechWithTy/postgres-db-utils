"""
Shared test configuration for db_utils tests
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.core.config import settings
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

# * Fixture for mocking ConnectionPool or DB pool
@pytest.fixture
def mock_db_pool():
    """Fixture providing a mock database pool object for test isolation."""
    return MagicMock(name="MockDbPool")

# Patch DB engine creation for integration tests to use SQLite in-memory DB and avoid SSL args
import pytest

@pytest.fixture(autouse=True)
def patch_db_engine(monkeypatch):
    import app.core.db_utils.db_config as db_config_mod
    from app.core.config import settings
    import os

    SQLITE_URL = "sqlite+aiosqlite:///:memory:"

    # Patch db_config.get_db_url to always return SQLite
    def fake_get_db_url():
        return SQLITE_URL
    monkeypatch.setattr(db_config_mod, "get_db_url", fake_get_db_url)

    # Patch db_config.create_engine to only pass SQLite-safe args
    def fake_create_engine():
        from sqlalchemy.ext.asyncio import create_async_engine
        db_url = fake_get_db_url()
        # ! Only pass SQLite-safe arguments for SQLite
        if db_url.startswith("sqlite"):
            # Defensive: ensure no pool arguments are passed
            assert "pool" not in [kwarg for kwarg in create_async_engine.__code__.co_varnames if kwarg.startswith("pool")], "Pool argument passed to SQLite create_async_engine"
            return create_async_engine(db_url, pool_pre_ping=True, echo=False)
        else:
            pool_config = db_config_mod.get_pool_config()
            return create_async_engine(
                db_url,
                pool_size=pool_config["pool_size"],
                max_overflow=pool_config["max_overflow"],
                pool_recycle=pool_config["pool_recycle"],
                pool_timeout=pool_config["pool_timeout"],
                pool_pre_ping=True,
                pool_use_lifo=True,
                echo=False,
            )
    monkeypatch.setattr(db_config_mod, "create_engine", fake_create_engine)

    # Patch settings.database fields to dummy values for SQLite, but only if they exist (to support mocks)
    for attr, value in [
        ("DB_USER", "test"),
        ("DB_PASSWORD", "test"),
        ("DB_NAME", "test"),
        ("DB_HOST", "localhost"),
        ("DB_PORT", 5432),
        ("DB_SSL_MODE", "disable"),
    ]:
        if hasattr(settings.database, attr):
            monkeypatch.setattr(settings.database, attr, value)

    # Patch commonly missing config fields on settings and submodels
    # METRICS_ENABLED (root)
    if hasattr(settings, "METRICS_ENABLED"):
        monkeypatch.setattr(settings, "METRICS_ENABLED", True)
    else:
        setattr(type(settings), "METRICS_ENABLED", True)

    # monitoring submodel
    monitoring_fields = [
        ("PROMETHEUS_ENABLED", True),
        ("PROMETHEUS_URL", "http://localhost:9090"),
        ("LOKI_URL", "http://localhost:3100"),
        ("GRAFANA_URL", "http://localhost:3000"),
        ("SENTRY_DSN", ""),
    ]
    for attr, value in monitoring_fields:
        if hasattr(settings.monitoring, attr):
            monkeypatch.setattr(settings.monitoring, attr, value)
        else:
            setattr(type(settings.monitoring), attr, value)

    # redis submodel
    redis_fields = [
        ("REDIS_HOST", "localhost"),
        ("REDIS_PORT", 6379),
        ("REDIS_PASSWORD", "test"),
        ("REDIS_DB", 0),
        ("REDIS_URL", "redis://localhost:6379/0"),
    ]
    for attr, value in redis_fields:
        if hasattr(settings.redis, attr):
            monkeypatch.setattr(settings.redis, attr, value)
        else:
            setattr(type(settings.redis), attr, value)

    # Patch email settings
    email_fields = [
        ("EMAILS_FROM_EMAIL", "info@example.com"),
        ("SMTP_TLS", True),
        ("SMTP_SSL", False),
        ("SMTP_PORT", 587),
        ("EMAILS_FROM_NAME", "Fast-Supabase-Api"),
        ("EMAIL_RESET_TOKEN_EXPIRE_HOURS", 48),
    ]
    for attr, value in email_fields:
        if hasattr(settings.email, attr):
            monkeypatch.setattr(settings.email, attr, value)
        else:
            setattr(type(settings.email), attr, value)

    # Patch METRICS_PORT on settings (root)
    if hasattr(settings, "METRICS_PORT"):
        monkeypatch.setattr(settings, "METRICS_PORT", 9090)
    else:
        setattr(type(settings), "METRICS_PORT", 9090)

    # Patch SQLALCHEMY_DATABASE_URI on MagicMock if used in any test config
    try:
        from unittest.mock import MagicMock
        setattr(MagicMock, "SQLALCHEMY_DATABASE_URI", property(lambda self: SQLITE_URL))
    except ImportError:
        pass

    # Patch any other referenced fields as needed below...

    # Robust patch: Remove DATABASE_URL from both the class and any instance, then patch as property
    import logging
    logger = logging.getLogger("test_patch_db_engine")
    from app.core.config import DatabaseSettings
    for cls in (type(settings.database), DatabaseSettings):
        # Remove property from class
        if hasattr(cls, "DATABASE_URL"):
            try:
                delattr(cls, "DATABASE_URL")
                logger.debug(f"Deleted DATABASE_URL property from {cls}")
            except (AttributeError, TypeError) as e:
                logger.debug(f"Could not delete DATABASE_URL property from {cls}: {e}")
        # Remove from all known instances
        for obj in [settings.database]:
            if hasattr(obj, "DATABASE_URL"):
                try:
                    del obj.DATABASE_URL
                    logger.debug(f"Deleted DATABASE_URL from instance {obj}")
                except Exception as e:
                    logger.debug(f"Could not delete DATABASE_URL from instance {obj}: {e}")
        # Set property on class
        setattr(cls, "DATABASE_URL", property(lambda self: SQLITE_URL))
        logger.debug(f"Set DATABASE_URL property on {cls} to always return SQLite URL")

    # Patch os.environ["DATABASE_URL"] in case any code reads it directly
    monkeypatch.setenv("DATABASE_URL", SQLITE_URL)

    # Patch SQLALCHEMY_DATABASE_URI property at the class level to always return SQLite URI
    monkeypatch.setattr(type(settings), "SQLALCHEMY_DATABASE_URI", property(lambda self: SQLITE_URL))

    yield

def _patched_metric_factory(factory, registry):
    def wrapper(*a, **kw):
        if 'registry' not in kw:
            kw['registry'] = registry
        return factory(*a, **kw)
    return wrapper

@pytest.fixture(autouse=True)
def clear_prometheus_registry():
    """Clear the patched prometheus_client registry before each test to prevent duplicated timeseries errors."""
    import prometheus_client
    registry = prometheus_client.REGISTRY
    if hasattr(registry, '_names_to_collectors'):
        registry._names_to_collectors.clear()
    if hasattr(registry, '_collector_to_names'):
        registry._collector_to_names.clear()
    if hasattr(registry, '_names_to_documentation'):
        registry._names_to_documentation.clear()

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
    # Valid Fernet key (generated for test use)
    ENCRYPTION_KEY = "7zQnWc9WkL8qv9rKZ9M5u5Xn6pQvWw6Q2a8q9Zt9vWw="
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
