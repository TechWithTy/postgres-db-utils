"""
Production-ready tests for sensitive.py
"""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Fixture to clear encryption singleton (future-proof, harmless if unused)
@pytest.fixture(autouse=True)
def clear_encryptor_singleton():
    try:
        from app.core.db_utils.encryption import DataEncryptor
        DataEncryptor._instance = None
    except ImportError:
        pass

pytestmark = pytest.mark.usefixtures("clear_encryptor_singleton")

from app.core.db_utils.sensitive import load_environment_files

class TestLoadEnvironmentFiles:
    """Test suite for environment file loading"""

    @patch('app.core.db_utils.sensitive.env_path', Path("/nonexistent"))
    @patch('app.core.db_utils.sensitive.load_dotenv')
    @patch('builtins.print')
    def test_load_env_file_not_found(self, mock_print, mock_load_dotenv):
        """Test behavior when .env file doesn't exist"""
        load_environment_files()
        
        mock_print.assert_called_with("No .env file found. Using system environment variables.")
        mock_load_dotenv.assert_not_called()


    def test_loads_actual_env_vars(self, tmp_path):
        """Test that environment variables are actually loaded from .env"""
        # Create a temporary .env file
        env_file = tmp_path / ".env"
        env_file.write_text("TEST_VAR=test_value")
        
        # Patch env_path to point to our test file
        with patch('app.core.db_utils.sensitive.env_path', env_file):
            # Clear any existing TEST_VAR
            os.environ.pop('TEST_VAR', None)
            
            # Load the environment
            load_environment_files()
            
            # Verify the variable was loaded
            assert os.getenv('TEST_VAR') == 'test_value'
