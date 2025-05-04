# Core Celery & Redis Best Practices

## Task Registration Patterns

### CPU-Bound Tasks
```python
@run_cpu_task_with_best_practices(
    config=CPUTaskConfig(
        credit_type="cpu_credits",
        credit_amount=5,
        cache_ttl=3600,
        permission_roles=["user", "admin"]
    )
)
def heavy_computation(data: dict) -> dict:
    # CPU-intensive work
    return process_data(data)
```

### I/O-Bound Tasks  
```python
@run_io_task_with_best_practices(
    config=IOTaskConfig(
        credit_type="io_credits",
        rate_limit=100,
        rate_window=60
    )
)
async def fetch_external_data(url: str) -> dict:
    # Network I/O work
    return await httpx.get(url).json()
```

### DB Tasks
```python
@run_db_task_with_best_practices(
    config=DBTaskConfig(
        credit_type="db_credits",
        max_retries=3,
        backoff=2
    )
)
async def complex_query(params: dict) -> list[dict]:
    # Database operations
    return await db.execute(query, params)
```

## Redis Caching Best Practices

### Cache Key Structure
Keys follow this pattern:
```
{module}.{function}:{auth_context}:{roles}:{args}:{kwargs}
```

### Cache Isolation
- User-specific data: Includes user ID in key for admins/users
- Role-based data: Includes permission roles in key
- Auth context: Falls back to auth token for non-user roles

## Deployment Considerations

### Celery Workers
```bash
# Dedicated worker for CPU tasks
celery -A app worker -Q cpu -c 2 -P solo --loglevel=info

# Dedicated worker for I/O tasks  
celery -A app worker -Q io -c 10 -P gevent --loglevel=info

# Dedicated worker for DB tasks
celery -A app worker -Q db -c 4 -P prefork --loglevel=info
```

### Redis Configuration
- Enable persistence (AOF + RDB)
- Set appropriate maxmemory policy
- Configure replica nodes for read scaling

## Scaling Strategies

### Horizontal Scaling
- Add worker nodes based on queue backlog
- Use `autoscale` for dynamic worker allocation:
  ```python
  app.conf.worker_autoscaler = {
      'min': 2, 
      'max': 10,
      'target_latency': 1.0
  }
  ```

### Queue Prioritization
```python
# In task config:
task_priority = 3  # 0-9 where 0 is highest
```

## Debugging Techniques

### Common Issues
1. **Stuck Tasks**:
   ```python
   from celery.app.control import inspect
   inspect().active()  # View running tasks
   ```

2. **Cache Misses**:
   - Verify key builder pattern
   - Check TTL values
   - Monitor hit/miss ratio

3. **Credit Issues**:
   ```python
   from app.core.credits import check_balance
   check_balance(user_id, credit_type)
   ```

## Performance Optimization

### Redis
- Pipeline frequent operations
- Use hash tags for cluster stability
- Enable compression for large values

### Celery
- **CPU tasks**: Use `-P solo` pool
- **I/O tasks**: Use `-P gevent/eventlet`
- **DB tasks**: Limit concurrency to DB connection pool size

### Task Design
- Chunk large workloads
- Use `chord` for parallel workflows
- Implement result backends for long-running tasks

## Monitoring Setup
```python
# Prometheus metrics example
from celery.contrib.monitoring import setup_metrics
setup_metrics(app)
```
