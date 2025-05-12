import logging

import redis.asyncio as redis
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.api.deps_supabase import get_supabase_db
from app.core.config import settings
from app.core.valkey_core.limiting.rate_limit import service_rate_limit

router = APIRouter()
logger = logging.getLogger(__name__)


async def check_db_health() -> bool:
    """Verify database connection health"""
    try:
        supabase = get_supabase_db()
        # Simple query to verify connection
        await supabase.rpc("version", {})
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return False


async def check_cache_health() -> bool:
    """Verify Redis cache connection health"""
    try:
        client = redis.from_url(settings.REDIS_URL)
        await client.ping()
        return True
    except Exception as e:
        logger.error(f"Cache health check failed: {str(e)}")
        return False


@router.get("/live")
@service_rate_limit
async def liveness_check():
    """K8s liveness probe - indicates container is running"""
    return {"status": "alive"}


@router.get("/ready")
@service_rate_limit
async def readiness_check():
    """K8s readiness probe - verifies service dependencies"""
    db_ok = await check_db_health()
    cache_ok = await check_cache_health()

    status_code = 200 if db_ok and cache_ok else 503
    return JSONResponse(
        content={
            "status": "ready" if status_code == 200 else "degraded",
            "components": {"database": db_ok, "cache": cache_ok},
        },
        status_code=status_code,
    )


@router.get("/health")
@service_rate_limit
async def health_check():
    """Comprehensive health check with metrics"""
    checks = {"database": await check_db_health(), "cache": await check_cache_health()}

    healthy = all(checks.values())
    status_code = 200 if healthy else 503

    return JSONResponse(
        content={"status": "healthy" if healthy else "unhealthy", "components": checks},
        status_code=status_code,
    )
