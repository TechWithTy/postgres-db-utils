# Valkey Caching Decorators & Utilities: Best Practices

This guide documents your production caching patterns with Valkey (Redis-compatible), including decorators, batch warming, stale cache, and design for DRY, SOLID, and observable FastAPI services.

---

## 1. Caching Decorators & Utilities

### 1.1 get_or_set_cache
Caches function results by key, with TTL, batch warming, and stale cache support.
```python
from app.core.valkey_core.cache.decorators import get_or_set_cache

@get_or_set_cache(key_fn=lambda *a, **k: f"user:{k['user_id']}", ttl=300)
async def get_user_profile(user_id):
    ...
```
- `key_fn`: Function to generate cache key from args/kwargs.
- `ttl`: Time-to-live in seconds.
- `warm_cache`: Preload cache for known keys (batch warming).
- `stale_ttl`: Serve stale data if backend is slow or fails.

### 1.2 Batch Warming
Efficiently preloads cache for a list of keys.
```python
@get_or_set_cache(key_fn=..., warm_cache=True)
async def get_many_items(ids: list):
    ...
```
- Use for dashboards, analytics, or any bulk fetch scenario.

### 1.3 Stale Cache
Serve slightly outdated data when backend is slow or unavailable.
```python
@get_or_set_cache(key_fn=..., ttl=300, stale_ttl=60)
async def get_expensive_data(...):
    ...
```
- Reduces user-facing errors and latency spikes.

---

## 2. Cache Algorithm Adapters

Valkey supports several advanced cache eviction policies. Choose the adapter that fits your workload:

### 2.1 FIFO Cache
Evicts oldest entry first. Good for queue-like workloads.
```python
from app.core.valkey_core.algorithims.caching.valkey_fifo_cache import ValkeyFIFOCache
cache = ValkeyFIFOCache()
await cache.set("key", value)
```

### 2.2 LIFO Cache
Evicts most recently added entry first. Useful for undo/redo stacks.
```python
from app.core.valkey_core.algorithims.caching.valkey_lifo_cache import ValkeyLIFOCache
cache = ValkeyLIFOCache()
await cache.set("key", value)
```

### 2.3 LRU Cache
Evicts least recently used entry. Best for general API/DB caching.
```python
from app.core.valkey_core.algorithims.caching.valkey_lru_cache import ValkeyLRUCache
cache = ValkeyLRUCache()
await cache.set("key", value)
```

### 2.4 MRU Cache
Evicts most recently used entry. Useful for hot/cold data separation.
```python
from app.core.valkey_core.algorithims.caching.valkey_mru_cache import ValkeyMRUCache
cache = ValkeyMRUCache()
await cache.set("key", value)
```

### 2.5 LFU Cache
Evicts least frequently used entry. Ideal for caching popular API/db results.
```python
from app.core.valkey_core.algorithims.caching.valkey_lfu_cache import ValkeyLFUCache
cache = ValkeyLFUCache()
await cache.set("key", value)
```

---

## 3. Usage Patterns

### 2.1 API Response Caching
Cache expensive or slow API responses for a short TTL.
```python
@get_or_set_cache(key_fn=..., ttl=60)
async def get_weather(city):
    ...
```

### 2.2 DB Query Caching
Cache DB query results to reduce load and latency.
```python
@get_or_set_cache(key_fn=..., ttl=300)
async def get_user_data(user_id):
    ...
```

### 2.3 External API Caching
Cache results from third-party APIs to save quota and improve speed.
```python
@get_or_set_cache(key_fn=..., ttl=600)
async def get_external_price(symbol):
    ...
```

---

## 3. Best Practices

- **Key Design:** Use clear, unique prefixes (e.g., `user:{id}`, `weather:{city}`) to avoid collisions.
- **Invalidation:** Invalidate cache on updates/deletes using Valkey `delete` or `expire`.
- **Observability:** Log cache hits/misses, expose Prometheus metrics for hit rate, latency, and errors.
- **Testing:** Mock cache in tests, verify both cache and fallback logic.
- **Security:** Never cache sensitive data unless encrypted and access-controlled.
- **Graceful Degradation:** Serve stale or fallback data if Valkey is unavailable.
- **Batching:** Use batch warming for high-volume or dashboard endpoints.
- **TTL Tuning:** Tune TTLs based on data volatility and user experience needs.

---

*See also: `valkey_cache.py` for core cache logic and connection pooling.*

*Last updated: 2025-05-13*
