# Database Query Optimizations Usage Guide

This module provides production-grade utilities for optimizing SQLAlchemy queries with:
- Circuit breaker & retry logic
- Redis caching
- Prometheus metrics
- Structured logging
- DRY patterns for FastAPI dependencies

## Quickstart Example

Optimize and cache a single-object query with circuit breaker protection:

```python
from app.core.db_utils.db_optimizations import QueryOptimizer

# Example: Get a User by ID with related fields optimized
user_query = QueryOptimizer.optimize_single_object_query(
    model_class=User,  # SQLAlchemy model
    query_params={"id": user_id},
    join_related_fields=["profile"],
    select_related_fields=["roles"],
    db_session=db_session
)
user = user_query.one_or_none()
```

- Results are cached in Redis (TTL: 5 min)
- Circuit breaker prevents DB overload on repeated failures
- Prometheus metrics track query counts, durations, and circuit trips

---

## Advanced Usage

### 1. Using QueryOptimizer Directly

- `optimize_single_object_query(...)`: For single-object lookups (uses cache, circuit breaker, metrics)
- `optimize_queryset(...)`: For bulk queries, with join/selectinload and retry logic

```python
query = db_session.query(MyModel)
optimized_query = QueryOptimizer.optimize_queryset(
    query=query,
    join_related_fields=["related_field1"],
    select_related_fields=["related_field2"]
)
results = optimized_query.all()
```

### 2. FastAPI Dependency Pattern with OptimizedQuerySetMixin

For DRY dependency injection in FastAPI:

```python
from app.core.db_utils.db_optimizations import OptimizedQuerySetMixin

class UserProfileQuerySet(OptimizedQuerySetMixin):
    model = UserProfile
    join_related_fields = ["user"]
    select_related_fields = ["roles"]

# In your FastAPI route
def get_user_profile_query(db=Depends(get_db)):
    return UserProfileQuerySet().get_query(db)
```

### 3. Customizing Circuit Breaker & Retry
- Circuit breaker: 5 failures, 30s timeout (see `@circuit` decorator)
- Retries: 3 attempts, 0.1s delay (see `MAX_RETRIES`)
- Adjust in `QueryOptimizer` if needed

### 4. Prometheus Metrics
- Query counts, durations, and circuit breaker trips are exported
- Integrate with your monitoring stack for alerting

### 5. Logging
- All optimizations and failures are logged with context

---

## Example: get_optimized_user_profile

```python
from app.core.db_utils.db_optimizations import get_optimized_user_profile

user_query = get_optimized_user_profile(user_id, db_session)
user_profile = user_query.one_or_none()
```
- Prefetches user relation for optimal access

---

## Troubleshooting & Best Practices

- Ensure Redis/Valkey and Prometheus are running for full feature set
- Use join/selectinload for all related fields to avoid N+1 queries
- If you see `CircuitBreakerError`, check DB health and logs
- For cache issues, clear Redis and retry
- Always pass an active SQLAlchemy session (`db_session`)
- For custom models, follow the provided patterns and type hints

---

## Reference: Main APIs
- `QueryOptimizer.optimize_single_object_query`
- `QueryOptimizer.optimize_queryset`
- `OptimizedQuerySetMixin`
- `get_optimized_user_profile`

---

*This guide is up to date as of 2025-05-13. For advanced patterns or troubleshooting, see inline code comments and Prometheus/Grafana dashboards.*
