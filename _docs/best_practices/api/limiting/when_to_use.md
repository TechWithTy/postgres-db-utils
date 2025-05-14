FastAPI Limiter is a popular package for rate limiting in FastAPI, and it uses Redis as its backend for distributed rate limiting out of the box. For most teams and standard API use-cases, the default documentation and usage patterns provided by FastAPI Limiter (with Redis) are sufficient and easy to follow.

When to Use Each Rate Limiting Algorithm (Valkey/Redis)

This guide explains when and how to use each rate limiting algorithm in your stack, with code patterns and best practices for FastAPI, Valkey, and custom business logic.

---

## 1. Layered Rate Limiting: FastAPI Limiter + Custom Valkey Logic

- **FastAPI Limiter** should be applied at the API route level as the initial protection layer. This provides a simple, robust, and easy-to-configure defense against basic abuse and accidental overuse.
- **Custom Valkey-based limiting (debounce, sliding window, token bucket, etc.)** should also be set at the route level for advanced business logic, multi-tenant rules, or where you need more control than FastAPI Limiter provides.
- This layered approach ensures both general API safety and enforcement of your unique business requirements.

---

## 2. Choosing a Rate Limiting Strategy

- **Debounce**: Allow an event only after a period of inactivity. Use for: email/SMS triggers, UI button spam, expensive operations.
- **Fixed Window**: Allow N requests per fixed time window (e.g., 100/min). Use for: simple per-user or per-IP API rate limits.
- **Sliding Window**: Like fixed window, but smoother and fairer. Use for: production APIs with bursty traffic, fairness.
- **Token Bucket**: Allow bursts up to a max, refill over time. Use for: APIs needing burst tolerance (e.g., 10 requests instantly, then refill at 1/sec).
- **Throttle**: Enforce a minimum interval between events. Use for: payment attempts, login attempts, brute-force protection.

---

When FastAPI Limiter Alone Is Sufficient
You only need basic per-endpoint or per-user rate limiting.
You don’t need custom logic for dynamic limits, advanced analytics, or multi-tenant support.
You’re fine with the default Redis-based backend and don’t need to swap for Valkey, Sentinel, or a custom backend.
You want to keep your stack simple and minimize custom code.

When to Add Custom Documentation or Examples
You use a non-standard Redis deployment (e.g., Valkey, Sentinel, Redis Cluster) and have custom connection logic.
You want to enforce complex, business-driven rate limits (e.g., per-plan, per-organization, burst + sustained, etc.).
You want to integrate rate limiting with your own logging, monitoring, or alerting stack.
You want to show how to combine FastAPI Limiter with other security layers (auth, credits, abuse detection).
Your team is new to distributed rate limiting and needs step-by-step setup, troubleshooting, or local dev tips.
Recommendation for Your Project
If your team is comfortable with the default FastAPI Limiter + Redis setup, and your rate limiting needs are straightforward, the official FastAPI Limiter docs are sufficient.
If you have custom Redis/Valkey logic, want to show integration with your own client, or need to explain advanced patterns (e.g., multi-tenant, dynamic limits), add a focused doc or section in your best practices folder. This helps future devs and avoids confusion.
Example: Custom Redis Integration Snippet
python
CopyInsert
from fastapi_limiter import FastAPILimiter
from app.core.valkey_core.client import client as ValkeyClient  # Your custom client

@app.on_event(\"startup\")
async def startup():
    await FastAPILimiter.init(ValkeyClient())
Summary:

For most use-cases, FastAPI Limiter’s docs are enough.
Add custom documentation only if you have non-standard Redis logic, advanced business rules, or want to show integration with your own stack.