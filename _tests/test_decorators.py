"""
Tests for database operation decorators.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from app.core.db_utils.decorators import (
    with_engine_connection,
    with_query_optimization,
    with_pool_metrics,
    with_secure_environment,
    with_encrypted_parameters,
    DatabaseError,
    ConnectionError,
    RetryableError
)

@pytest.mark.asyncio
async def test_with_engine_connection():
    """Test engine connection decorator."""
    mock_func = AsyncMock(return_value="result")
    decorated = with_engine_connection(mock_func)
    
    with patch('app.core.db_utils.decorators.create_engine') as mock_engine:
        mock_conn = AsyncMock()
        mock_engine.return_value.connect.return_value.__aenter__.return_value = mock_conn
        
        result = await decorated()
        
        assert result == "result"
        mock_func.assert_called_once_with(mock_conn)

@pytest.mark.asyncio
async def test_with_engine_connection_retry():
    """Test retry logic in engine connection decorator."""
    mock_func = AsyncMock(side_effect=[ConnectionError("First fail"), "result"])
    decorated = with_engine_connection(mock_func)
    
    with patch('app.core.db_utils.decorators.create_engine') as mock_engine, \
         patch('app.core.db_utils.decorators.logger') as mock_logger:
        
        mock_conn = AsyncMock()
        mock_engine.return_value.connect.side_effect = [
            Exception("First fail"),
            mock_conn.__aenter__.return_value
        ]
        
        result = await decorated()
        
        assert result == "result"
        assert mock_engine.call_count == 2
        assert mock_logger.warning.call_count == 1

@pytest.mark.asyncio
async def test_with_engine_connection_failure():
    """Test failure after max retries."""
    mock_func = AsyncMock(side_effect=ConnectionError("Failed"))
    decorated = with_engine_connection(mock_func)
    
    with patch('app.core.db_utils.decorators.create_engine') as mock_engine, \
         patch('app.core.db_utils.decorators.settings') as mock_settings:
        
        mock_settings.DB_CONNECTION_RETRIES = 2
        mock_engine.return_value.connect.side_effect = Exception("Failed")
        
        with pytest.raises(ConnectionError):
            await decorated()
        
        assert mock_engine.call_count == 2

@pytest.mark.asyncio
async def test_with_query_optimization():
    """Test query optimization decorator."""
    mock_func = AsyncMock(return_value="result")
    decorated = with_query_optimization(mock_func)
    
    mock_model = MagicMock()
    mock_query = MagicMock()
    
    result = await decorated(mock_model, query=mock_query)
    
    assert result == "result"
    assert "query" in mock_func.call_args[1]
    assert mock_func.call_args[1]["query"] != mock_query  # Should be optimized

@pytest.mark.asyncio
async def test_with_pool_metrics():
    """Test pool metrics decorator."""
    mock_func = AsyncMock(return_value="result")
    decorated = with_pool_metrics(mock_func)
    
    with patch('app.core.db_utils.decorators.get_pool_metrics') as mock_metrics:
        mock_metrics.return_value = {"test": "metrics"}
        result = await decorated()
        
        assert result == "result"
        mock_metrics.assert_called_once()

@pytest.mark.asyncio
async def test_with_secure_environment():
    """Test secure environment decorator."""
    mock_func = AsyncMock(return_value="result")
    decorated = with_secure_environment(mock_func)
    
    with patch('app.core.db_utils.decorators.load_environment_files') as mock_load:
        result = await decorated()
        
        assert result == "result"
        mock_load.assert_called_once()

@pytest.mark.asyncio
async def test_with_encrypted_parameters():
    """Test parameter encryption decorator."""
    mock_func = AsyncMock(return_value={"secret": "encrypted_value"})
    decorated = with_encrypted_parameters(mock_func)
    
    with patch('app.core.db_utils.decorators.settings') as mock_settings, \
         patch('app.core.db_utils.decorators.encrypt_data') as mock_encrypt, \
         patch('app.core.db_utils.decorators.decrypt_data') as mock_decrypt:
        
        mock_settings.SENSITIVE_FIELDS = ["password"]
        mock_encrypt.return_value = "encrypted_value"
        mock_decrypt.return_value = "decrypted_value"
        
        result = await decorated(password="test")
        
        assert result == {"secret": "decrypted_value"}
        mock_encrypt.assert_called_once_with("test")
        mock_decrypt.assert_called_once_with("encrypted_value")

@pytest.mark.asyncio
async def test_with_encrypted_parameters_error_handling():
    """Test encryption decorator error handling."""
    mock_func = AsyncMock(return_value={"secret": "value"})
    decorated = with_encrypted_parameters(mock_func)
    
    with patch('app.core.db_utils.decorators.settings') as mock_settings, \
         patch('app.core.db_utils.decorators.DataEncryptor') as mock_encryptor:
        
        mock_settings.SENSITIVE_FIELDS = ["password"]
        mock_encryptor.return_value.encrypt.side_effect = Exception("Encryption failed")
        
        with pytest.raises(DatabaseError):
            await decorated(password="test")
        
        mock_encryptor.return_value.encrypt.assert_called_once()
