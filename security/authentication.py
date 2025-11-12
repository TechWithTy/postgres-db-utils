"""
Authentication utilities for FastAPI endpoints using Supabase as the backend auth provider.
Supports JWT, API key with RBAC scopes, and OAuth authentication. Uses SupabaseAuthService utilities for validation.
"""

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Optional, List, Dict
from fastapi import HTTPException, Security, status, Depends, Request
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, SecurityScopes
from app.core.third_party_integrations.supabase_home.auth import SupabaseAuthService
from app.core.third_party_integrations.supabase_home.client import supabase
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# Initialize Supabase auth service
supabase_auth_service = SupabaseAuthService()

# Define security schemes as module-level singletons
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_scheme = APIKeyHeader(name="X-API-Key")


# ======================================================
# API Key Scope Definitions
# ======================================================

DEFAULT_SCOPES = [
    "read:profile",      # Read user profile
    "write:profile",     # Update user profile
    "read:data",         # Read user data (leads, campaigns, etc.)
    "write:data",        # Create/update user data
    "read:analytics",    # Access analytics data
    "write:settings",    # Modify account settings
    "read:billing",      # Read billing information
    "write:billing",     # Modify billing settings
    "read:credentials",  # Read OAuth/API credentials for integrations
    "admin:users",       # Admin operations on users
    "admin:system",      # System-level admin operations
    "webhook:receive",   # Receive webhook events
    "api:usage",         # API usage statistics
]

USER_DEFAULT_SCOPES = [
    "read:profile", "write:profile", "read:data", "write:data", 
    "read:analytics", "read:billing", "read:credentials", 
    "webhook:receive", "api:usage"
]

ADMIN_SCOPES = DEFAULT_SCOPES  # Admins get all scopes


# ======================================================
# API Key Management Functions
# ======================================================

async def validate_api_key_with_scopes(api_key: str, required_scopes: List[str] = None) -> Dict[str, Any]:
    """
    Validate API key and check if it has required scopes.
    Returns user info and key metadata if valid.
    Raises HTTPException if invalid or insufficient permissions.
    """
    if not api_key or not api_key.startswith("dsk_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format"
        )
    
    # Hash the provided key to compare with stored hash
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    try:
        # Look up key in database
        supabase_client = supabase.get_raw_client()
        result = supabase_client.table("user_api_keys")\
            .select("*")\
            .eq("key_hash", key_hash)\
            .eq("is_active", True)\
            .execute()
        
        if not result.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        
        key_data = result.data[0]
        
        # Check if key is expired
        if key_data.get("expires_at"):
            expires_at = datetime.fromisoformat(key_data["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_at:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="API key expired"
                )
        
        # Get scopes from user_api_key_permissions junction table
        permissions_result = supabase_client.table("user_api_key_permissions")\
            .select("permissions(name)")\
            .eq("api_key_id", key_data["id"])\
            .execute()
        
        key_scopes = []
        if permissions_result.data:
            key_scopes = [perm["permissions"]["name"] for perm in permissions_result.data if perm.get("permissions")]
        
        # Check required scopes
        if required_scopes:
            missing_scopes = set(required_scopes) - set(key_scopes)
            if missing_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Missing scopes: {', '.join(missing_scopes)}"
                )
        
        # Update last_used_at timestamp in background
        try:
            supabase_client.table("user_api_keys")\
                .update({"last_used_at": datetime.now(timezone.utc).isoformat()})\
                .eq("id", key_data["id"])\
                .execute()
        except Exception as e:
            logger.warning(f"Failed to update last_used_at for API key: {e}")
        
        # For API key authentication, create a minimal user object
        # Since we validated the API key exists and belongs to a valid user,
        # we can create a simplified user object with the user_id
        user_data = {
            "id": key_data["user_id"],
            "email": f"api-key-user-{key_data['user_id']}",  # Placeholder
            "app_metadata": {},
            "user_metadata": {},
            "api_key_authenticated": True,
            "api_key_id": key_data["id"],
            "api_key_name": key_data["name"]
        }
        
        return {
            "user": user_data,
            "auth_method": "api_key",
            "key_id": key_data["id"],
            "key_name": key_data["name"],
            "scopes": key_scopes,
            "key_data": key_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service error"
        )


async def create_api_key(
    user_id: str, 
    name: str, 
    description: str = None,
    scopes: List[str] = None,
    expires_at: datetime = None
) -> Dict[str, Any]:
    """
    Create a new API key for a user with specified scopes.
    Returns the plain API key (only shown once) and metadata.
    """
    # Generate secure API key with dealscale prefix
    api_key = f"dsk_{secrets.token_urlsafe(37)}"  # dsk = dealscale key
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    # Use default scopes if none provided
    if scopes is None:
        scopes = USER_DEFAULT_SCOPES
    
    # Validate scopes
    invalid_scopes = set(scopes) - set(DEFAULT_SCOPES)
    if invalid_scopes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scopes: {', '.join(invalid_scopes)}"
        )
    
    try:
        supabase_client = supabase.get_raw_client()
        
        # Create API key record
        key_record = {
            "user_id": user_id,
            "name": name,
            "key_hash": key_hash,
            "key_prefix": api_key[:8],
            "scopes": scopes,  # Store scopes in the array field
            "expires_at": expires_at.isoformat() if expires_at else None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True
        }
        
        # Add metadata if description provided
        if description:
            key_record["metadata"] = {"description": description}
        
        key_result = supabase_client.table("user_api_keys").insert(key_record).execute()
        
        if not key_result.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create API key"
            )
        
        key_id = key_result.data[0]["id"]
        
        # Scopes are already stored in the API key record
        # No need for junction table - using the scopes array field
        
        return {
            "api_key": api_key,  # Only returned once!
            "key_id": key_id,
            "name": name,
            "scopes": scopes,
            "expires_at": expires_at,
            "warning": "Save this key securely - it won't be shown again"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )



# ======================================================
# Unified Authentication Functions
# ======================================================

# * Dependency for extracting JWT token with error handling
async def get_optional_jwt_token(
    request: Request,
) -> str | None:
    """Extract JWT token from Authorization header without raising errors"""
    authorization = request.headers.get("Authorization")
    if not authorization:
        return None
    
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            return None
        return token
    except ValueError:
        return None

# * Main authentication dependency that supports both JWT and API keys with scope validation
async def authenticate_user_with_scopes(
    required_scopes: list[str],
    request: Request,
    auth_service: SupabaseAuthService = Depends(lambda: supabase_auth_service)
) -> Dict[str, Any]:
    """
    Authenticate a user using JWT, API key with scope validation, or OAuth.
    Returns a dict with user info, auth_type, and validated scopes.
    Raises 401/403 if no valid credentials or insufficient permissions.
    
    Args:
        required_scopes: List of required permission scopes
        request: FastAPI request object to extract headers
        auth_service: Supabase authentication service
    
    Returns:
        Dict containing:
        - user: User information dict
        - auth_method: "jwt" or "api_key"
        - scopes: List of user's available scopes
        - validated_scopes: List of validated required scopes
    """
    
    # Extract tokens from headers
    authorization = request.headers.get("Authorization")
    api_key_header = request.headers.get("X-API-Key")
    
    jwt_token = None
    api_key = None
    
    # Parse Authorization header
    if authorization:
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() == "bearer":
                if token.startswith("dsk_"):
                    api_key = token  # API key in Authorization header
                else:
                    jwt_token = token  # JWT token
        except ValueError:
            pass
    
    # Check X-API-Key header
    if api_key_header and api_key_header.startswith("dsk_"):
        api_key = api_key_header
    
    # Try API key first (if provided)
    if api_key:
        return await validate_api_key_with_scopes(api_key, required_scopes)
    # Try JWT token
    if jwt_token:
        try:
            user = auth_service.get_user_by_token(jwt_token)
            # For JWT, we assume full permissions (user is authenticated through web)
            return {
                "user": user, 
                "auth_method": "jwt",
                "scopes": DEFAULT_SCOPES,  # JWT gets all scopes by default
                "token": jwt_token
            }
        except Exception as e:
            logger.debug(f"JWT validation failed: {e}")
            # Fall through to unauthorized
    
    # No valid authentication method provided
    if required_scopes:
        authenticate_value = f'Bearer scope="{" ".join(required_scopes)}"'
    else:
        authenticate_value = "Bearer"
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required: provide JWT token or API key",
        headers={"WWW-Authenticate": authenticate_value}
    )


# * Legacy authentication dependency for backward compatibility
async def get_optional_token_for_legacy(
    request: Request,
) -> dict[str, str | None]:
    """Extract both JWT and API key from headers for legacy functions"""
    authorization = request.headers.get("Authorization")
    api_key_header = request.headers.get("X-API-Key")
    
    jwt_token = None
    api_key = None
    
    if authorization:
        try:
            scheme, token = authorization.split(" ", 1)
            if scheme.lower() == "bearer":
                jwt_token = token
        except ValueError:
            pass
    
    if api_key_header:
        api_key = api_key_header
        
    return {"jwt_token": jwt_token, "api_key": api_key}

async def authenticate_user(
    tokens: dict = Depends(get_optional_token_for_legacy),
    oauth_token: Optional[str] = None,  # For future extensibility
) -> dict:
    """
    Legacy authenticate_user function for backward compatibility.
    Authenticate a user using JWT, API key, or OAuth without scope requirements.
    Returns a dict with user info and auth_type ('jwt', 'api_key', or 'oauth').
    Raises 401 if no valid credentials are provided or invalid.
    """
    jwt_token = tokens.get("jwt_token")
    api_key = tokens.get("api_key")
    
    # Check if the jwt_token is actually an API key
    if jwt_token and jwt_token.startswith("dsk_"):
        api_key = jwt_token
        jwt_token = None
    
    # Try API key first if we have one
    if api_key:
        try:
            result = await validate_api_key_with_scopes(api_key, required_scopes=None)
            return {
                "user": result["user"],
                "auth_method": "api_key",
                "scopes": result["scopes"]
            }
        except Exception as e:
            logger.debug(f"API key validation failed: {e}")
    
    # Try JWT if we have one
    if jwt_token:
        try:
            user = supabase_auth_service.get_user_by_token(jwt_token)
            return {"user": user, "auth_method": "jwt"}
        except Exception as e:
            logger.debug(f"JWT validation failed: {e}")
    
    # Try OAuth token
    if oauth_token:
        try:
            user = supabase_auth_service.get_user_by_token(oauth_token)
            return {"user": user, "auth_method": "oauth"}
        except Exception as e:
            logger.debug(f"OAuth validation failed: {e}")
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, 
        detail="No valid credentials"
    )


# ======================================================
# Scoped Authentication Dependencies
# ======================================================

def require_scopes(scopes: List[str]):
    """
    Dependency factory for requiring specific scopes.
    Usage: @app.get("/data", dependencies=[Depends(require_scopes(["read:data"]))])
    """
    async def scoped_auth(
        verified_user = Security(authenticate_user_with_scopes, scopes=scopes)
    ):
        return verified_user
    return scoped_auth


def require_any_scope(scopes: List[str]):
    """
    Dependency factory for requiring ANY of the specified scopes (OR logic).
    Usage: @app.get("/data", dependencies=[Depends(require_any_scope(["read:data", "admin:system"]))])
    """
    async def any_scope_auth(
        tokens: dict = Depends(get_optional_token_for_legacy),
    ):
        jwt_token = tokens.get("jwt_token")
        api_key = tokens.get("api_key")
        
        if jwt_token:
            try:
                user = supabase_auth_service.get_user_by_token(jwt_token)
                return {"user": user, "auth_method": "jwt", "scopes": DEFAULT_SCOPES}
            except Exception:
                pass
        
        if api_key:
            try:
                result = await validate_api_key_with_scopes(api_key, required_scopes=None)
                user_scopes = result["scopes"]
                
                # Check if user has ANY of the required scopes
                if not any(scope in user_scopes for scope in scopes):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Requires any of these scopes: {', '.join(scopes)}"
                    )
                
                return result
            except HTTPException:
                raise
            except Exception:
                pass
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    return any_scope_auth


# ======================================================
# API Key Management Functions (continued)
# ======================================================

async def list_user_api_keys(user_id: str) -> List[Dict[str, Any]]:
    """List all API keys for a user with their scopes."""
    try:
        supabase_client = supabase.get_raw_client()
        result = supabase_client.table("user_api_keys")\
            .select("*")\
            .eq("user_id", user_id)\
            .eq("is_active", True)\
            .order("created_at", desc=True)\
            .execute()
        
        keys = []
        for key_data in result.data:
            keys.append({
                "id": key_data["id"],
                "name": key_data["name"],
                "key_prefix": key_data["key_prefix"],
                "scopes": key_data.get("scopes", []),
                "created_at": key_data["created_at"],
                "expires_at": key_data["expires_at"],
                "last_used_at": key_data["last_used_at"],
                "is_active": key_data["is_active"],
                "metadata": key_data.get("metadata", {})
            })
        
        return keys
        
    except Exception as e:
        logger.error(f"Error listing API keys: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list API keys"
        )


async def revoke_api_key(user_id: str, key_id: str) -> bool:
    """Revoke (deactivate) an API key."""
    try:
        supabase_client = supabase.get_raw_client()
        result = supabase_client.table("user_api_keys")\
            .update({"is_active": False, "revoked_at": datetime.now(timezone.utc).isoformat()})\
            .eq("id", key_id)\
            .eq("user_id", user_id)\
            .execute()
        
        return len(result.data) > 0
        
    except Exception as e:
        logger.error(f"Error revoking API key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )


# Optionally, utility for admin lookup
async def admin_lookup_user(user_id: str) -> dict:
    """
    Retrieve a user by their Supabase UID (admin privileges).
    """
    return supabase_auth_service.get_user(user_id)
