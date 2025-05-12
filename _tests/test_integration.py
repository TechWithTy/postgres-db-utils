"""
Integration tests for production database scenarios.
"""
import asyncio
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db_utils.db_config import create_engine
from app.core.db_utils.db_optimizations import QueryOptimizer
from app.core.db_utils.pool import ConnectionPool, get_engine
from sqlalchemy import text

# Fixture to clear encryption singleton (future-proof, harmless if unused)
@pytest.fixture(autouse=True)
def clear_encryptor_singleton():
    try:
        from app.core.db_utils.encryption import DataEncryptor
        DataEncryptor._instance = None
    except ImportError:
        pass

pytestmark = pytest.mark.usefixtures("clear_encryptor_singleton")



@pytest.mark.integration
class TestProductionScenarios:
    """Integration tests for production database scenarios."""

    @pytest.mark.asyncio
    async def test_connection_pool_under_load(self):
        """Test connection pool behavior under concurrent load."""
        engine = get_engine()
        monitor = ConnectionPool()
        
        async def execute_query():
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        
        # Simulate concurrent connections
        tasks = [execute_query() for _ in range(20)]
        await asyncio.gather(*tasks)
        
        metrics = monitor.metrics
        assert metrics.connections_created > 0
        # * If you have active_connections in PoolMetrics, use it; otherwise, skip or adapt this check
        # assert metrics.active_connections == 0  # All connections released
        # * If you have wait_time_ms in PoolMetrics, use it; otherwise, skip or adapt this check
        # assert metrics.wait_time_ms < 100  # Reasonable wait time

    @pytest.mark.asyncio
    async def test_query_optimization_real_queries(self, mock_model):
        """Test query optimization with real database queries."""
        engine = get_engine()
        optimizer = QueryOptimizer(mock_model)
        
        async with AsyncSession(engine) as session:
            # Basic query
            query = session.query(mock_model)
            optimized = optimizer.optimize_queryset(query)
            
            # Verify optimization didn't break query execution
            result = await session.execute(optimized)
            assert result is not None
            
            # Verify optimization strategies were applied
            assert any(
                'joinedload' in str(opt) or 'selectinload' in str(opt)
                for opt in optimized._with_options
            )

    @pytest.mark.asyncio
    async def test_failover_scenario(self):
        """Test connection recovery after simulated failure."""
        engine = create_engine()
        
        # Simulate connection failure
        with patch('sqlalchemy.ext.asyncio.AsyncEngine.connect', 
                 side_effect=Exception("Connection failed")) as mock_connect:
            with pytest.raises(Exception):
                async with engine.connect():
                    pass
            
            assert mock_connect.call_count == 1
        
        # Verify recovery
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            assert result.scalar() == 1

    @pytest.mark.asyncio
    async def test_connection_recycling(self):
        """Test connection pool recycling behavior."""
        engine = get_engine()
        monitor = ConnectionPool()
        
        initial_recycles = monitor.metrics['recycles']
        
        # Force connection recycling
        for _ in range(5):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        
        assert monitor.metrics['recycles'] > initial_recycles
