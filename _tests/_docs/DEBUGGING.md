# Debugging Test Failures

## Common Issues and Solutions

### 1. Missing Dependencies
```bash
# Install required test dependencies
pip install sqlalchemy cryptography pytest-asyncio
```

### 2. Pytest Configuration Warnings
Add this to your `pyproject.toml` or `pytest.ini`:
```ini
[pytest]
asyncio_fixture_loop_scope = "function"
```

### 3. Test Collection Errors
- Verify all test files have valid Python names (no special characters)
- Ensure all imports are available in the virtual environment

### 4. Running Specific Tests
```bash
# Run a single test file
pytest app/core/db_utils/_tests/test_encryption.py -v

# Run tests with dependency checks
pytest --durations=10 --cov=app/core/db_utils
```

### 5. Environment Setup
```bash
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install development dependencies
pip install -e .[test]
```
