"""
Tests for production-ready database configuration.
"""
import os
import pytest
from unittest.mock import patch

from app.core.db_utils.db_config import (
    get_db_url,
    create_engine,
    POOL_SIZE,
    MAX_OVERFLOW,
    POOL_RECYCLE
)
from app.core.db_utils.pool import (
    ConnectionPoolMonitor,
    get_pool_metrics
)

@pytest.fixture
def mock_env(monkeypatch):
    """Fixture for mocking environment variables."""
    monkeypatch.setenv('DATABASE_URL', 'postgresql+asyncpg://user:pass@localhost:5432/db')
    monkeypatch.setenv('ENV', 'test')

class TestDatabaseConfig:
    def test_get_db_url_production(self, monkeypatch):
        """Test SSL enforcement in production."""
        monkeypatch.setenv('ENV', 'production')
        url = get_db_url()
        assert 'sslmode=require' in url
    
    def test_get_db_url_missing(self, monkeypatch):
        """Test missing DATABASE_URL raises error."""
        monkeypatch.delenv('DATABASE_URL', raising=False)
        with pytest.raises(ValueError):
            get_db_url()
    
    def test_create_engine_config(self, mock_env):
        """Test engine creation with proper config."""
        engine = create_engine()
        assert engine.pool.size() == POOL_SIZE
        assert engine.pool._max_overflow == MAX_OVERFLOW
        assert engine.pool._recycle == POOL_RECYCLE

class TestConnectionPoolMonitor:
    def test_monitor_initial_state(self):
        """Test monitor initializes with zero values."""
        monitor = ConnectionPoolMonitor()
        assert monitor.metrics['total_connections'] == 0
        assert monitor.metrics['active_connections'] == 0
    
    def test_connection_tracking(self):
        """Test connection acquisition/release tracking."""
        monitor = ConnectionPoolMonitor()
        monitor.connection_acquired()
        assert monitor.metrics['total_connections'] == 1
        assert monitor.metrics['active_connections'] == 1
        
        monitor.connection_released()
        assert monitor.metrics['active_connections'] == 0
    
    def test_get_pool_metrics(self, mock_env):
        """Test global metrics access."""
        metrics = get_pool_metrics()
        assert isinstance(metrics, dict)
        assert 'total_connections' in metrics
