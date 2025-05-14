"""
FastAPI Example: Secure Per-Endpoint Auth Policy using AuthServiceJobConfig

How it works with your current Auth model:
- Each route is mapped to an endpoint name (e.g., 'get_user_info')
- AuthServiceJobConfig.endpoint_auth defines the required policy (auth level, roles, scopes, MFA) for each endpoint
- AuthServiceJobConfig.default_endpoint_auth provides a secure fallback for any unlisted endpoint
- The enforcement dependency reads the policy for the current endpoint and checks the current user against it
- User info (roles, scopes, MFA, etc.) would be extracted from a JWT or session in production
- This pattern ensures that all endpoints are protected according to your config, with no accidental public routes

How to use:
- Adjust get_current_user to extract real user info from your JWT/session (see todo in code)
- Use make_secured_route('endpoint_name') in your route to enforce the correct policy
- Add or update endpoint policies in AuthServiceJobConfig as your API evolves

- Demonstrates usage of endpoint_auth and default_endpoint_auth
- Shows role/scope/MFA checks
- Production-ready enforcement pattern
"""

from fastapi import FastAPI, Depends, HTTPException, status, Request
from typing import Callable
from app.core.db_utils._docs.best_practices.api.best_practices.config.AuthServiceJobConfig import (
    AuthServiceJobConfig, EndpointAuthConfig, AuthPolicy
)

# Simulate current user (in real app, extract from JWT/session)
def get_current_user(request: Request):
    # todo: Replace with real JWT/session extraction
    return {
        "username": "alice",
        "roles": ["user"],
        "scopes": ["read:user"],
        "mfa_passed": True,
        "is_authenticated": True,
    }

# --- Auth Enforcement Dependency ---
def enforce_auth_policy(
    endpoint_name: str,
    config: AuthServiceJobConfig = Depends(),
    user: dict = Depends(get_current_user),
) -> None:
    """
    Enforce the per-endpoint auth policy using the new SecurityConfig-driven AuthServiceJobConfig.
    """
    # Get the endpoint's SecurityConfig (raises KeyError if endpoint not configured)
    auth_config = config.endpoint_configs[endpoint_name].auth

    # 1. Public endpoint (no auth required)
    if not auth_config.permission_roles_required and not auth_config.user_permissions_required and not auth_config.mfa_required:
        return

    # 2. Must be authenticated
    if not user.get("is_authenticated"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    # 3. Role check
    if auth_config.permission_roles_required:
        if not any(role in user.get("roles", []) for role in auth_config.permission_roles_required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")

    # 4. Scope/permission check
    if auth_config.user_permissions_required:
        if not all(scope in user.get("scopes", []) for scope in auth_config.user_permissions_required):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing required permission/scope")

    # 5. MFA check
    if auth_config.mfa_required and not user.get("mfa_passed"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="MFA required")

# --- FastAPI App and Routes ---
app = FastAPI()
config = AuthServiceJobConfig()  # In real app, inject/configure as needed

def make_secured_route(endpoint_name: str) -> Callable:
    def dependency():
        return enforce_auth_policy(endpoint_name, config)
    return Depends(dependency)

@app.get("/sign_up")
def sign_up():
    return {"msg": "Sign up is public"}

@app.get("/get_user_info")
def get_user_info(dep=make_secured_route("get_user_info")):
    return {"msg": "User info"}

@app.get("/admin_only")
def admin_only(dep=make_secured_route("admin_only")):
    return {"msg": "Admin only"}

@app.get("/health")
def health():
    return {"msg": "OK"}

@app.get("/unlisted")
def unlisted(dep=make_secured_route("unlisted")):
    return {"msg": "This uses the default (secure) policy"}

@app.get("/has_admin_only_config")
def has_admin_only_config():
    """
    Checks if the AuthServiceJobConfig includes an 'admin_only' endpoint in endpoint_configs.
    Returns the config if present, otherwise returns False.
    """
    from app.core.db_utils._docs.best_practices.api.best_practices.config.AuthServiceJobConfig import AuthServiceJobConfig
    config = AuthServiceJobConfig()
    admin_only = config.endpoint_configs.get("admin_only")
    if admin_only:
        return {"admin_only_present": True, "admin_only_config": admin_only.model_dump()}
    return {"admin_only_present": False}

# todo: Add more routes and real JWT extraction for production
