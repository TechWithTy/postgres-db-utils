import sys
from pathlib import Path

from dotenv import load_dotenv

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Add the apps directory to the Python path
sys.path.insert(0, str(BASE_DIR / "apps"))

# Define path for the environment file
env_path = BASE_DIR.parent / ".env"


def load_environment_files():
    """Load environment variables from .env file if exists"""
    if env_path.exists():
        path_str = str(env_path)  # Use raw path string
        print(f"Loading environment file: {path_str}")
        load_dotenv(path_str, override=True)
    else:
        print("No .env file found. Using system environment variables.")
