"""
Tests for database connection pooling
"""

import logging
import os
from dotenv import load_dotenv
from pathlib import Path
import pytest
from sqlalchemy import text
from unittest.mock import patch

# Fixture to clear encryption singleton (future-proof, harmless if unused)
@pytest.fixture(autouse=True)
def clear_encryptor_singleton():
    try:
        from app.core.db_utils.encryption import DataEncryptor
        DataEncryptor._instance = None
    except ImportError:
        pass

pytestmark = pytest.mark.usefixtures("clear_encryptor_singleton")

logger = logging.getLogger(__name__)

from app.core.config import settings
from app.core.db_utils import pool

# Load environment variables
env_path = Path(__file__).parent.parent.parent.parent.parent / ".env"
load_dotenv(env_path)
print(f"Loading .env from: {env_path}")
print(f"File exists: {env_path.exists()}")


class TestDatabasePool:
    """Test database connection pooling"""

    @pytest.mark.asyncio
    async def test_get_db_session(self, mock_db_session):
        """Test session lifecycle management"""
        # Patch ConnectionPool.get_connection to return our mock session
        with patch("app.core.db_utils.pool.ConnectionPool.get_connection", return_value=mock_db_session):
            session_gen = pool.get_db_session()
            session = await session_gen.__anext__()
            assert session is mock_db_session
            try:
                await session_gen.__anext__()
            except StopAsyncIteration:
                pass

    @pytest.mark.asyncio
    async def test_supabase_url_conversion(self, mock_db_pool):
        """Test supabase URL conversion"""
        with patch.object(
            settings.database,
            "SUPABASE_DB_DIRECT_CONNECTION",
            "postgresql://mock:mock@localhost/mock",
        ):
            engine = pool.get_engine()
            assert engine is not None

    @pytest.mark.asyncio
    async def test_config_priority(self, mock_db_pool):
        """Test configuration priority"""
        with (
            patch.object(
                settings.database,
                "SUPABASE_DB_DIRECT_CONNECTION",
                "postgresql://mock:mock@localhost/mock",
            ),
            patch("app.core.db_utils.db_config.get_db_url", return_value="postgresql://mock:mock@localhost/mock"),
        ):
            engine = pool.get_engine()
            assert engine is not None

    # @pytest.mark.asyncio
    # async def test_real_database_connection(self, caplog):
    #     """Integration test with real database"""
    #     # Debug output
    #     caplog.set_level(logging.INFO)
    #     logger.info(
    #         f"Env SUPABASE_DB_CONNECTION_DIRECT: {os.environ.get('SUPABASE_DB_CONNECTION_DIRECT')}"
    #     )
    #     logger.info(
    #         f"Settings SUPABASE_DB_CONNECTION_DIRECT: {settings.database.SUPABASE_DB_CONNECTION_DIRECT}"
    #     )

    #     # Get URL from settings (which should use env vars)
    #     db_url = settings.database.SUPABASE_DB_CONNECTION_DIRECT or settings.database.DATABASE_URL

    #     if not db_url or "[YOUR-PASSWORD]" in db_url:
    #         safe_url = (
    #             db_url.replace(":[YOUR-PASSWORD]", ":[REDACTED]") if db_url else "None"
    #         )
    #         logger.warning(f"Invalid database URL: {safe_url}")
    #         pytest.skip(f"Invalid database URL: {safe_url}")

    #     logger.info(
    #         f"Attempting connection to: {db_url.replace(':[^@]*@', ':[REDACTED]@')}"
    #     )

    #     engine = pool.get_engine()
    #     try:
    #         async with engine.connect() as conn:
    #             result = await conn.execute(text("SELECT 1"))
    #             assert result.scalar() == 1
    #     except Exception as e:
    #         logger.error(f"Connection failed: {str(e)}")
    #         pytest.skip(f"Connection failed: {str(e)}")

    # @pytest.mark.asyncio
    # async def test_invalid_url_handling(self):
    #     """Test error handling for invalid URLs"""
    #     # Test empty URL
    #     with patch.object(settings, "DATABASE_URL", ""):
    #         with pytest.raises(ValueError, match="No database URL configured"):
    #             pool.get_engine()

    #     # Test invalid format
    #     with patch.object(settings, "DATABASE_URL", "invalid://url"):
    #         with pytest.raises(ValueError, match="must start with postgresql"):
    #             pool.get_engine()
