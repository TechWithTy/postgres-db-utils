"""
Database configuration module with production-ready settings.
"""
import os

from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import TimeoutSettings, settings

# Initialize timeout settings
timeout_settings = TimeoutSettings()

# Pool configuration should be evaluated inside a function for test patching

def get_pool_config():
    timeout_settings = TimeoutSettings()
    return {
        "pool_size": int(getattr(settings, 'DB_POOL_SIZE', 5)),
        "max_overflow": int(getattr(settings, 'DB_MAX_OVERFLOW', 10)),
        "pool_recycle": int(getattr(settings, 'DB_POOL_RECYCLE', 3600)),
        "pool_timeout": int(getattr(settings, 'DB_POOL_TIMEOUT', timeout_settings.POSTGRES)),
    }

def get_db_url() -> str:
    """
    Get production-ready DB URL with SSL enforcement.
    """
    ssl_mode = getattr(settings.database, 'DB_SSL_MODE', 'require')
    ssl_root_cert = getattr(settings.database, 'DB_SSL_ROOT_CERT', None)
    
    url = f"postgresql+asyncpg://{settings.database.DB_USER}:{settings.database.DB_PASSWORD}@{settings.database.DB_HOST}:{settings.database.DB_PORT}/{settings.database.DB_NAME}"
    
    ssl_params = {
        'ssl': 'require',
        'sslrootcert': ssl_root_cert
    } if ssl_mode == 'require' else {}
    
    return f"{url}?{'&'.join(f'{k}={v}' for k,v in ssl_params.items())}"

from sqlalchemy.engine.url import make_url

def create_engine():
    """
    Create and return a production-configured async database engine.
    Features:
    - Connection validation
    - SSL enforcement
    - Optimized pooling
    """
    db_url = get_db_url()
    url_obj = make_url(db_url)
    is_sqlite = url_obj.get_backend_name() == "sqlite"

    if is_sqlite:
        # ! SQLite/aiosqlite does NOT support pool_size, max_overflow, etc.
        # ! Only pass supported arguments to avoid TypeError in tests.
        return create_async_engine(
            db_url,
            echo=bool(getattr(settings, 'SQL_ECHO', False)),
            connect_args={},
        )
    else:
        pool_config = get_pool_config()
        return create_async_engine(
            db_url,
            pool_size=pool_config["pool_size"],
            max_overflow=pool_config["max_overflow"],
            pool_recycle=pool_config["pool_recycle"],
            pool_timeout=pool_config["pool_timeout"],
            pool_pre_ping=True,
            pool_use_lifo=True,
            echo=bool(getattr(settings, 'SQL_ECHO', False)),
            connect_args={
                'command_timeout': pool_config["pool_timeout"],
                'ssl': 'prefer' if getattr(settings, 'ENV', 'test') == 'production' else None
            }
        )
