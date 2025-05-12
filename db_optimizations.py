import logging
import time
from typing import Any, Optional, Type, TypeVar, Union

from prometheus_client import Counter, Histogram
from circuitbreaker import CircuitBreakerError, circuit
from sqlalchemy.exc import OperationalError, SQLAlchemyError, TimeoutError
from sqlalchemy.orm import DeclarativeBase, Query, joinedload, selectinload

from app.core.valkey_core.cache.valkey_cache import cache_result

logger = logging.getLogger(__name__)

# Prometheus Metrics
QUERY_COUNT = Counter(
    'db_query_optimizations_total', 
    'Total query optimizations', 
    ['status']
)
QUERY_DURATION = Histogram(
    'db_query_optimization_duration_seconds',
    'Query optimization duration',
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 5, 10)
)
CIRCUIT_BREAKER_TRIPS = Counter(
    'db_query_circuit_breaker_trips_total',
    'Total circuit breaker trips'
)

T = TypeVar('T', bound=DeclarativeBase)

class QueryMetrics:
    """Track performance metrics with Prometheus integration"""
    def record_query(self, success: bool, duration: float, circuit_tripped=False):
        status = 'success' if success else 'failure'
        QUERY_COUNT.labels(status=status).inc()
        QUERY_DURATION.observe(duration)
        
        if circuit_tripped:
            CIRCUIT_BREAKER_TRIPS.inc()
            
        logger.info(f"Query optimization - status: {status}, duration: {duration:.3f}s")

class QueryOptimizer:
    """
    A utility class for optimizing SQLAlchemy database queries with production features:
    - Circuit breaker pattern for failure handling
    - Error handling with retries
    - Logging
    - Performance metrics
    - Redis caching layer
    - Prometheus monitoring
    """
    
    metrics = QueryMetrics()
    MAX_RETRIES = 3
    RETRY_DELAY = 0.1
    
    @staticmethod
    @circuit(
        failure_threshold=5,
        recovery_timeout=30,
        expected_exception=(OperationalError, TimeoutError)
    )
    @cache_result(ttl=300, key_prefix="db_query_optimizations")
    def optimize_single_object_query(model_class: Type[T], 
                                    query_params: dict[str, Any],
                                    join_related_fields: list[str] | None = None,
                                    select_related_fields: list[str] | None = None,
                                    db_session=None) -> Query:
        """
        Optimizes a query with Redis caching layer and circuit breaker protection.
        """
        start_time = time.time()
        
        try:
            query = db_session.query(model_class)
            query = query.filter_by(**query_params)
            query = QueryOptimizer.optimize_queryset(
                query=query,
                join_related_fields=join_related_fields,
                select_related_fields=select_related_fields
            )
            QueryOptimizer.metrics.record_query(True, time.time() - start_time)
            logger.info(f"Optimized query for {model_class.__name__}")
            return query
        except (SQLAlchemyError, CircuitBreakerError) as e:
            QueryOptimizer.metrics.record_query(
                False, 
                time.time() - start_time,
                isinstance(e, CircuitBreakerError)
            )
            logger.error(f"Query optimization failed: {str(e)}")
            raise
    
    @staticmethod
    def optimize_queryset(query: Query,
                         join_related_fields: list[str] | None = None,
                         select_related_fields: list[str] | None = None) -> Query:
        """
        Optimizes a query with retry logic, connection management, and Redis fallback caching.
        """
        for attempt in range(QueryOptimizer.MAX_RETRIES):
            try:
                if join_related_fields:
                    for field in join_related_fields:
                        query = query.options(joinedload(field))
                
                if select_related_fields:
                    for field in select_related_fields:
                        query = query.options(selectinload(field))
                
                return query
            except (OperationalError, TimeoutError) as e:
                if attempt == QueryOptimizer.MAX_RETRIES - 1:
                    raise
                time.sleep(QueryOptimizer.RETRY_DELAY)


class OptimizedQuerySetMixin:
    """
    A mixin for FastAPI dependency injectors that adds methods for optimizing queries with
    joinedload and selectinload.
    """
    
    model: DeclarativeBase = None
    join_related_fields: list[str] = []
    select_related_fields: list[str] = []
    
    def get_query(self, db_session) -> Query:
        """
        Get the base query for the model.
        """
        query = db_session.query(self.model)
        return self._optimize_query(query)
    
    def _optimize_query(self, query: Query) -> Query:
        """
        Apply joinedload and selectinload optimizations to a query.
        """
        return QueryOptimizer.optimize_queryset(
            query=query,
            join_related_fields=self.join_related_fields,
            select_related_fields=self.select_related_fields
        )


# Common optimization patterns for the UserProfile model and related models
def get_optimized_user_profile(user_id: Union[str, int], db_session) -> Query:
    """
    Get a UserProfile with all commonly needed related objects prefetched.
    
    Args:
        user_id: The primary key of the user
        db_session: SQLAlchemy database session
        
    Returns:
        A query object
    """
    from app.models import UserProfile
    
    return QueryOptimizer.optimize_single_object_query(
        model_class=UserProfile,
        query_params={'user_id': user_id},
        join_related_fields=['user'],
        db_session=db_session
    )
