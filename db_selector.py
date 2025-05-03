import os

from app.core.config import settings


def get_db_client():
    # Try to get values from FastAPI settings first, then fall back to env vars
    supabase_url = getattr(settings, "SUPABASE_URL", "") or os.getenv("SUPABASE_URL", "")
    supabase_key = getattr(settings, "SUPABASE_ANON_KEY", "") or os.getenv("SUPABASE_ANON_KEY", "")
    postgres_server = getattr(settings, "POSTGRES_SERVER", "") or os.getenv("POSTGRES_SERVER", "")
    postgres_user = getattr(settings, "POSTGRES_USER", "") or os.getenv("POSTGRES_USER", "")
    
    # Check for Supabase configuration
    if supabase_url.strip() and supabase_key.strip():
        from app.core.third_party_integrations.supabase_home.client import supabase
        return supabase
    # Check for PostgreSQL configuration
    elif postgres_server.strip() and postgres_user.strip():
        from sqlmodel import Session
        from app.core.db import engine
        return Session(engine)
    else:
        raise RuntimeError(
            "No database configuration found. Set SUPABASE_URL/SUPABASE_ANON_KEY or POSTGRES_SERVER/POSTGRES_USER."
        )
