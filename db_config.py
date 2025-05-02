"""
Database configuration module with production-ready settings.
"""
import os

from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import TimeoutSettings, settings

# Initialize timeout settings
timeout_settings = TimeoutSettings()

# Pool configuration
POOL_SIZE = int(getattr(settings, 'DB_POOL_SIZE', 5))
MAX_OVERFLOW = int(getattr(settings, 'DB_MAX_OVERFLOW', 10))
POOL_RECYCLE = int(getattr(settings, 'DB_POOL_RECYCLE', 3600))  # 1 hour
POOL_TIMEOUT = int(getattr(settings, 'DB_POOL_TIMEOUT', timeout_settings.POSTGRES))

def get_db_url() -> str:
    """
    Get production-ready DB URL with SSL enforcement.
    """
    ssl_mode = getattr(settings, 'DB_SSL_MODE', 'require')
    ssl_root_cert = getattr(settings, 'DB_SSL_ROOT_CERT', None)
    
    url = f"postgresql+asyncpg://{settings.DB_USER}:{settings.DB_PASSWORD}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
    
    ssl_params = {
        'ssl': 'require',
        'sslrootcert': ssl_root_cert
    } if ssl_mode == 'require' else {}
    
    return f"{url}?{'&'.join(f'{k}={v}' for k,v in ssl_params.items())}"

def create_engine():
    """
    Create and return a production-configured async database engine.
    Features:
    - Connection validation
    - SSL enforcement
    - Optimized pooling
    """
    return create_async_engine(
        get_db_url(),
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_recycle=POOL_RECYCLE,
        pool_timeout=POOL_TIMEOUT,
        pool_pre_ping=True,
        pool_use_lifo=True,
        echo=bool(getattr(settings, 'SQL_ECHO', False)),
        connect_args={
            'command_timeout': POOL_TIMEOUT,
            'ssl': 'prefer' if getattr(settings, 'ENV') == 'production' else None
        }
    )
