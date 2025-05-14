# CORS & CSRF Middleware Best Practices

This guide explains how to use production-grade CORS and CSRF middleware in your Starlette or FastAPI applications using DRY, environment-driven utilities from `core.db_utils.security.oauth_scope`.

---

## ⭐️ Quick Start: Installation

```bash
pip install starlette starlette-csrf
```

---

## 1. CORS Middleware Setup

Use the provided utility to configure CORS from environment variables:

```python
from starlette.middleware.cors import CORSMiddleware
from core.db_utils.security.oauth_scope import get_cors_middleware_config

app.add_middleware(CORSMiddleware, **get_cors_middleware_config())
```

- **Environment Variable:**
  - `CORS_ALLOWED_ORIGINS` (comma-separated list, e.g. `https://yourdomain.com,https://admin.yourdomain.com`)

---

## 2. CSRF Middleware Setup

Use the Starlette CSRF middleware for cookie/session-based CSRF protection:

```python
from starlette_csrf import CSRFMiddleware
from core.db_utils.security.oauth_scope import get_csrf_middleware_config

app.add_middleware(CSRFMiddleware, **get_csrf_middleware_config())
```

- **Environment Variables:**
  - `CSRF_SECRET` (required, use a strong random value!)
  - `CSRF_COOKIE_SECURE` (`True` for prod)
  - `CSRF_COOKIE_SAMESITE` (`lax` or `strict`)
  - `CSRF_HEADER_NAME` (default: `x-csrftoken`)
  - `CSRF_COOKIE_NAME` (default: `csrftoken`)

---

## 3. Example: FastAPI Entrypoint

```python
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from starlette_csrf import CSRFMiddleware
from core.db_utils.security.oauth_scope import get_cors_middleware_config, get_csrf_middleware_config

app = FastAPI()
app.add_middleware(CORSMiddleware, **get_cors_middleware_config())
app.add_middleware(CSRFMiddleware, **get_csrf_middleware_config())
```

---

## Utilization Example

### CORS Middleware
```python
from starlette.middleware.cors import CORSMiddleware
from core.db_utils.security.oauth_scope import get_cors_middleware_config
app.add_middleware(CORSMiddleware, **get_cors_middleware_config())
```

### CSRF Middleware
```python
from starlette_csrf import CSRFMiddleware
from core.db_utils.security.oauth_scope import get_csrf_middleware_config
app.add_middleware(CSRFMiddleware, **get_csrf_middleware_config())
```
```

---

## 4. Example: Starlette Entrypoint

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette_csrf import CSRFMiddleware
from core.db_utils.security.oauth_scope import get_cors_middleware_config, get_csrf_middleware_config

routes = [...]

middleware = [
    Middleware(CORSMiddleware, **get_cors_middleware_config()),
    Middleware(CSRFMiddleware, **get_csrf_middleware_config()),
]

app = Starlette(routes=routes, middleware=middleware)
```

---

## 5. Security Best Practices

- **Never use `*` for CORS origins in production.**
- **Always set a strong `CSRF_SECRET` and keep it out of source control.**
- **Set `CSRF_COOKIE_SECURE=True` and `CSRF_COOKIE_SAMESITE` to `lax` or `strict` in production.**
- **Test your setup in staging before deploying to prod.**

---

## 6. Troubleshooting

- If you see unresolved import errors, ensure you have installed both `starlette` and `starlette-csrf`.
- Make sure your environment variables are loaded before the app starts.

---

## 7. References
- [Starlette CORS Middleware](https://www.starlette.io/middleware/#corsmiddleware)
- [starlette-csrf PyPI](https://pypi.org/project/starlette-csrf/)
- [OWASP CSRF Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

---

*Maintained by the Lead Ignite Backend Team – last updated 2025-05-13*
