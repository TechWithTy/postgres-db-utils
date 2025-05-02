"""
Database Connection Pool with:
- Circuit breaker pattern
- Prometheus metrics endpoint
- Async support

Metrics Endpoint:
- /metrics - Prometheus format metrics:
  * db_connection_attempts_total
  * db_connection_state
  * db_connection_latency_seconds

Configure via environment variables:
- METRICS_ENABLED=true/false
- METRICS_PORT=9090
"""

import logging
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from circuitbreaker import circuit
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client import start_http_server as start_metrics_server
from sqlalchemy.event import listens_for
from sqlalchemy.exc import DisconnectionError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

logger = logging.getLogger(__name__)

# Prometheus Metrics
DB_CONNECTION_ATTEMPTS = Counter(
    "db_connection_attempts_total", "Total connection attempts", ["status"]
)

DB_CONNECTION_STATE = Gauge(
    "db_connection_state",
    "Current connection pool state (0=Healthy, 1=Degraded, 2=Unavailable)",
)

DB_CONNECTION_LATENCY = Histogram(
    "db_connection_latency_seconds",
    "Connection acquisition latency",
    buckets=[0.1, 0.5, 1, 2, 5],
)


class PoolState(Enum):
    HEALTHY = auto()
    DEGRADED = auto()
    UNAVAILABLE = auto()


@dataclass
class PoolMetrics:
    connections_created: int = 0
    connections_reused: int = 0
    errors: int = 0
    failed_attempts: int = 0
    state: PoolState = PoolState.HEALTHY


class ConnectionPool:
    _instance = None
    _lock = threading.Lock()

    # Configuration defaults
    DEFAULT_POOL_SIZE = 5
    DEFAULT_MAX_OVERFLOW = 10
    DEFAULT_POOL_RECYCLE = 1800  # 30 minutes
    MAX_RETRIES = 3
    CIRCUIT_BREAKER_THRESHOLD = 5

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialize()
                    # Start metrics server if enabled
                    if settings.METRICS_ENABLED:
                        start_metrics_server(settings.METRICS_PORT)
                        logger.info(
                            "Started metrics server on port %d", 
                            settings.METRICS_PORT
                        )
        return cls._instance

    def _initialize(self):
        """Initialize with production-grade validation"""
        self._validate_pool_config()
        self._engine: Optional[AsyncEngine] = None
        self._session_factory = None
        self.metrics = PoolMetrics()
        self._last_failure_time = None
        self._failure_count = 0
        logger.info("Initialized connection pool with Prometheus metrics")

    def _validate_pool_config(self):
        """Validate pool configuration meets production requirements"""
        if not settings.DATABASE_URL:
            raise ValueError("DATABASE_URL must be configured")

        if self.DEFAULT_POOL_SIZE <= 0:
            raise ValueError("Pool size must be positive")

    @circuit(
        failure_threshold=5,
        recovery_timeout=60,
        expected_exception=(OperationalError, DisconnectionError),
        name="database_connection",
    )
    async def get_connection(self) -> AsyncSession:
        """Get connection with metrics tracking"""
        start_time = time.time()
        DB_CONNECTION_ATTEMPTS.labels(status="attempt").inc()

        try:
            session = await self._acquire_connection()
            DB_CONNECTION_STATE.set(self.metrics.state.value)
            DB_CONNECTION_LATENCY.observe(time.time() - start_time)
            DB_CONNECTION_ATTEMPTS.labels(status="success").inc()
            return session
        except Exception as e:
            DB_CONNECTION_ATTEMPTS.labels(status="failure").inc()
            DB_CONNECTION_STATE.set(PoolState.UNAVAILABLE.value)
            raise

    async def _acquire_connection(self) -> AsyncSession:
        attempt = 0
        last_error = None

        while attempt < self.MAX_RETRIES:
            attempt += 1
            try:
                if not self._engine:
                    await self._initialize_pool()

                session = self._session_factory()
                await self._test_connection(session)
                self._record_success()
                logger.debug("Acquired healthy connection (attempt %d)", attempt)
                return session

            except (OperationalError, DisconnectionError) as e:
                last_error = e
                logger.warning(
                    "Connection attempt %d/%d failed: %s",
                    attempt,
                    self.MAX_RETRIES,
                    str(e),
                )
                if attempt < self.MAX_RETRIES:
                    delay = self._get_retry_delay(attempt)
                    logger.info("Waiting %.2fs before retry", delay)
                    time.sleep(delay)

        self._record_failure()
        logger.error("All connection attempts failed")
        raise OperationalError(
            "All connection attempts failed", None, None
        ) from last_error

    def _get_retry_delay(self, attempt: int) -> float:
        """Exponential backoff for retries"""
        return min(2**attempt, 10)  # Cap at 10 seconds

    def _record_success(self):
        """Reset failure count on successful operation"""
        self._failure_count = 0
        self.metrics.state = PoolState.HEALTHY

    def _record_failure(self):
        """Track failures and update pool state"""
        self.metrics.errors += 1
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._failure_count >= self.CIRCUIT_BREAKER_THRESHOLD:
            self.metrics.state = PoolState.UNAVAILABLE
        elif self._failure_count >= self.CIRCUIT_BREAKER_THRESHOLD // 2:
            self.metrics.state = PoolState.DEGRADED

    async def _test_connection(self, session: AsyncSession):
        """Validate the connection is still healthy"""
        try:
            await session.execute("SELECT 1")
        except Exception as e:
            await session.close()
            raise OperationalError(
                f"Connection test failed: {str(e)}", None, None
            ) from e

    async def close(self):
        """Cleanup all connections"""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    @asynccontextmanager
    async def session_scope(self):
        """Provide transactional scope around series of operations"""
        session = await self.get_connection()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def _initialize_pool(self):
        # Get URL from settings
        db_url = getattr(settings, "SUPABASE_DB_CONNECTION_DIRECT", None) or getattr(
            settings, "DATABASE_URL", None
        )

        if not db_url:
            raise ValueError("No database URL configured in settings")

        if not db_url.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError(
                "Invalid database URL - must start with postgresql:// or postgresql+asyncpg://"
            )

        # Validate settings with detailed error messages
        def get_setting(name, default):
            value = getattr(settings, name, None)
            if value == "" or value is None:
                print(f"Warning: {name} is empty, using default: {default}")
                return default
            try:
                return int(value) if name != "SQL_ECHO" else bool(value)
            except (ValueError, TypeError):
                print(
                    f"Warning: Invalid {name} value '{value}', using default: {default}"
                )
                return default

        pool_size = get_setting("DB_POOL_SIZE", 5)
        max_overflow = get_setting("DB_MAX_OVERFLOW", 10)
        pool_recycle = get_setting("DB_POOL_RECYCLE", 1800)
        pool_timeout = get_setting("DB_POOL_TIMEOUT", 30)
        sql_echo = get_setting("SQL_ECHO", False)

        # Ensure proper URL format
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        self._engine = create_async_engine(
            db_url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_recycle=pool_recycle,
            pool_timeout=pool_timeout,
            echo=sql_echo,
        )

        # Add event listeners for monitoring
        @listens_for(self._engine.sync_engine, "connect")
        def receive_connect(dbapi_connection, connection_record):
            self.metrics.connections_created += 1

        @listens_for(self._engine.sync_engine, "close")
        def receive_close(dbapi_connection, connection_record):
            self.metrics.connections_reused += 1

        self._session_factory = sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )


async def get_db_session():
    """Get a database session with automatic cleanup"""
    async with ConnectionPool().session_scope() as session:
        yield session
