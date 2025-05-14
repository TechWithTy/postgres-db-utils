# Database Selector Usage Guide

This module provides a unified interface for selecting the correct database client (Supabase or PostgreSQL) at runtime, based on environment variables or FastAPI settings.

---

## Quickstart Example

```python
from app.core.db_utils.db_selector import get_db_client

db_client = get_db_client()

# If Supabase is configured, returns the Supabase client.
# If PostgreSQL is configured, returns a SQLModel Session.
# Raises RuntimeError if no configuration is found.
```

---

## How it Works

- Checks for Supabase credentials (`SUPABASE_URL` and `SUPABASE_ANON_KEY`) in FastAPI settings or environment.
- If not found, checks for PostgreSQL credentials (`POSTGRES_SERVER` and `POSTGRES_USER`).
- Returns the appropriate client for your application context.
- Fails fast with a clear error if neither is configured.

---

## Configuration

Set one of the following in your environment or `settings`:

- For Supabase:
  - `SUPABASE_URL`
  - `SUPABASE_ANON_KEY`
- For PostgreSQL:
  - `POSTGRES_SERVER`
  - `POSTGRES_USER`

---

## Best Practices

- Prefer environment variables for secrets and connection info.
- Use this selector in shared libraries or services that must support both Supabase and Postgres.
- Always handle `RuntimeError` for missing configuration in your app startup or dependency injection.
- Do not mix clients in the same request context.

---

## Troubleshooting

- **RuntimeError:** Ensure you have set the required environment variables for either Supabase or PostgreSQL.
- **Supabase import error:** Ensure `app.core.third_party_integrationsclient.supabase` is installed and importable.
- **Session/engine error:** Ensure SQLModel and your DB engine are correctly configured.

---

## Reference

- `get_db_client() -> supabase | Session`
  - Returns Supabase client or SQLModel Session, depending on configuration.

---

*Guide updated 2025-05-13. For advanced usage, see inline code comments.*
