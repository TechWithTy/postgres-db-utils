"""
Production-ready tests for db_optimizations.py with enhanced coverage.
"""
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Query, joinedload, selectinload

from app.core.db_utils.db_optimizations import OptimizedQuerySetMixin, QueryOptimizer


@pytest.fixture
def mock_db_session():
    return MagicMock()

@pytest.fixture
def mock_model():
    """Fixture providing a mock model with properly configured relationships"""
    from sqlalchemy import ForeignKey, Integer
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

    class Base(DeclarativeBase):
        pass

    class RelatedModel(Base):
        __tablename__ = "related_model"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)

    class ManyRelatedModel(Base):
        __tablename__ = "many_related_model"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        mock_model_id: Mapped[int] = mapped_column(ForeignKey("mock_model.id"))
        mock_model: Mapped["MockModel"] = relationship(
            back_populates="many_related_field"
        )

    class MockModel(Base):
        __tablename__ = "mock_model"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        related_id: Mapped[int] = mapped_column(ForeignKey("related_model.id"))

        related_field: Mapped["RelatedModel"] = relationship(foreign_keys=[related_id])
        many_related_field: Mapped[list["ManyRelatedModel"]] = relationship(
            back_populates="mock_model",
            foreign_keys=lambda: ManyRelatedModel.mock_model_id,
        )

    return MockModel

@pytest.mark.asyncio
class TestQueryOptimizer:
    """Test suite for QueryOptimizer class with production scenarios."""

    async def test_optimize_single_object_query(self, mock_db_session, mock_model):
        """Test query optimization with joinedload and selectinload."""
        optimizer = QueryOptimizer(mock_model)
        query = optimizer.optimize_query(mock_db_session.query(mock_model))
        
        # Verify optimization strategies are applied
        assert any(isinstance(opt, (joinedload, selectinload)) 
                  for opt in query._with_options)

    async def test_optimize_queryset(self, mock_model):
        """Test query optimization on existing queryset."""
        queryset = MagicMock(spec=Query)
        optimizer = QueryOptimizer(mock_model)
        optimized = optimizer.optimize_queryset(queryset)
        
        assert optimized is not None
        queryset.options.assert_called()

    # New production test cases
    async def test_optimize_with_custom_strategies(self, mock_db_session, mock_model):
        """Test optimization with custom strategy configuration."""
        custom_strategies = {
            'related_field': joinedload,
            'many_related_field': selectinload
        }
        optimizer = QueryOptimizer(mock_model, strategies=custom_strategies)
        query = optimizer.optimize_query(mock_db_session.query(mock_model))
        
        assert len(query._with_options) == 2

    async def test_performance_metrics_logging(self, mock_db_session, mock_model):
        """Test query optimization logs performance metrics."""
        with patch('app.core.db_utils.db_optimizations.logger.debug') as mock_log:
            optimizer = QueryOptimizer(mock_model)
            optimizer.optimize_query(mock_db_session.query(mock_model))
            
            assert mock_log.called
            assert 'optimized' in mock_log.call_args[0][0]

@pytest.mark.asyncio
class TestOptimizedQuerySetMixin:
    """Test suite for OptimizedQuerySetMixin with production features."""
    
    model = mock_model
    join_related_fields = [mock_model.related_field]
    select_related_fields = [mock_model.many_related_field]

    async def test_get_query(self, mock_db_session, mock_model):
        """Test query generation with optimizations."""
        class TestQuerySet(OptimizedQuerySetMixin):
            model = mock_model
            join_related_fields = [mock_model.related_field]
            select_related_fields = [mock_model.many_related_field]

        queryset = TestQuerySet()
        query = queryset.get_query(mock_db_session)
        
        assert query is not None
        assert any(isinstance(opt, (joinedload, selectinload)) 
                  for opt in query._with_options)

    # New production test cases
    async def test_empty_optimization_fields(self, mock_db_session, mock_model):
        """Test behavior with empty optimization fields."""
        class TestQuerySet(OptimizedQuerySetMixin):
            model = mock_model
            join_related_fields = []
            select_related_fields = []

        queryset = TestQuerySet()
        query = queryset.get_query(mock_db_session)
        
        assert query is not None
        assert not hasattr(query, '_with_options')

    async def test_optimization_with_session_factory(self, mock_db_session, mock_model):
        """Test optimization works with session factory pattern."""
        class TestQuerySet(OptimizedQuerySetMixin):
            model = mock_model
            join_related_fields = [mock_model.related_field]
            
            @property
            def session(self):
                return mock_db_session

        queryset = TestQuerySet()
        query = queryset.get_query()
        
        assert query is not None
        assert any(isinstance(opt, joinedload) for opt in query._with_options)
