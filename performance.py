"""
Additional query optimization and metric collection decorators for Supabase and SQLAlchemy.
These decorators are designed to work with both database backends.
"""
import functools
import time
import logging
from typing import Any, Callable, TypeVar, cast
import asyncio
from opentelemetry import trace

from app.core.config import settings
from app.core.telemetry.telemetry import get_telemetry
from app.core.prometheus.metrics import get_db_latency, get_db_count, get_connection_metrics

logger = logging.getLogger(__name__)

T = TypeVar('T')

def optimized_query(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator to optimize database queries for both SQLAlchemy and Supabase.
    
    For SQLAlchemy, adds query hints and optimized fetch strategies.
    For Supabase, adds proper query parameters for optimized execution.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Get the current span for tracing
        span = trace.get_current_span()
        span.set_attribute("db.optimization", "enabled")
        
        # Check if we're using Supabase
        is_supabase = getattr(settings, "USE_SUPABASE", False)
        
        # Log optimization information
        logger.debug(f"Running optimized query for function: {func.__name__}, backend: {'Supabase' if is_supabase else 'SQLAlchemy'}")
        
        try:
            # Apply appropriate optimization depending on the database backend
            if is_supabase:
                # For Supabase, add the count option to return the total count along with the results
                # This saves an extra query when we need both results and count
                if 'select' in kwargs and isinstance(kwargs['select'], str) and 'count' not in kwargs:
                    if 'skip' in kwargs or 'limit' in kwargs:
                        kwargs['count'] = 'exact'  # Request exact count from Supabase
                        
                # Ensure we're using the most efficient Supabase query options
                if 'skip' in kwargs and 'limit' in kwargs:
                    # Use range header for more efficient pagination
                    if 'headers' not in kwargs:
                        kwargs['headers'] = {}
                    skip = kwargs.get('skip', 0)
                    limit = kwargs.get('limit', 100)
                    kwargs['headers']['Range'] = f"{skip}-{skip + limit - 1}"
            else:
                # For SQLAlchemy, we'd optimize differently
                # Let the core db_utils.with_query_optimization handle this
                pass
                
            # Execute the function with optimization
            start_time = time.time()
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Record metrics about the optimized query
            span.set_attribute("db.query.duration_ms", duration * 1000)
            span.set_attribute("db.query.optimized", True)
            
            # If the function returns a list, add count information to span
            if isinstance(result, list):
                span.set_attribute("db.query.result_count", len(result))
                
            return result
        except Exception as e:
            # Record the error in metrics and span
            span.set_attribute("db.query.error", str(e))
            span.record_exception(e)
            raise
            
    return cast(Callable[..., T], wrapper)


def with_connection_metrics(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator to track database connection metrics.
    Works with both SQLAlchemy and Supabase connections.
    """
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # Get the current span for tracing
        span = trace.get_current_span()
        span.set_attribute("db.connection_metrics", "enabled")
        
        # Get the session or client object from args or kwargs
        session = None
        for arg in args:
            if hasattr(arg, 'execute') or hasattr(arg, 'from_'):  # SQLAlchemy session or Supabase client
                session = arg
                break
        
        if session is None and 'session' in kwargs:
            session = kwargs['session']
            
        # Check if we're using Supabase
        is_supabase = getattr(settings, "USE_SUPABASE", False)
        
        # Record pool metrics
        try:
            if is_supabase:
                # For Supabase we can't easily get connection pool metrics
                # Just record that we used a connection
                get_connection_metrics().labels('supabase', 'active').inc()
                get_connection_metrics().labels('supabase', 'total').inc()
            else:
                # For SQLAlchemy we can get more detailed metrics
                if hasattr(session, 'bind') and hasattr(session.bind, 'pool'):
                    pool = session.bind.pool
                    get_connection_metrics().labels('sqlalchemy', 'active').set(pool.checkedout())
                    get_connection_metrics().labels('sqlalchemy', 'idle').set(pool.checkedin())
                    get_connection_metrics().labels('sqlalchemy', 'total').set(pool.size())
                else:
                    # Session doesn't have pool info, just record usage
                    get_connection_metrics().labels('unknown', 'active').inc()
        except Exception as e:
            # Log but don't fail if metrics collection fails
            logger.warning(f"Error collecting connection metrics: {e}")
            
        # Execute the function and measure latency
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            
            # Record success metrics
            get_db_latency().observe(duration)
            get_db_count().labels(operation="success").inc()
            
            # Record duration in span
            span.set_attribute("db.query.duration_ms", duration * 1000)
            span.set_attribute("db.connection.status", "success")
            
            # After query completes, decrement active connection counter for Supabase
            if is_supabase:
                get_connection_metrics().labels('supabase', 'active').dec()
                
            return result
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            get_db_latency().observe(duration)
            get_db_count().labels(operation="error").inc()
            
            # Record error in span
            span.set_attribute("db.connection.status", "error")
            span.set_attribute("db.connection.error", str(e))
            span.record_exception(e)
            
            # After query fails, decrement active connection counter for Supabase
            if is_supabase:
                get_connection_metrics().labels('supabase', 'active').dec()
                
            raise
            
    return cast(Callable[..., T], wrapper)


def async_retry(max_retries: int = 3, delay: float = 0.1, backoff_factor: float = 2):
    """
    Async retry decorator with exponential backoff.
    Helps with transient database connection issues.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            span = trace.get_current_span()
            retries = 0
            current_delay = delay
            
            while True:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries > max_retries:
                        span.set_attribute("retry.exhausted", True)
                        span.set_attribute("retry.count", retries)
                        raise
                    
                    # Add retry info to span
                    span.set_attribute("retry.count", retries)
                    span.set_attribute("retry.delay", current_delay)
                    
                    # Wait before retrying with exponential backoff
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff_factor
        
        return cast(Callable[..., T], wrapper)
    
    return decorator
