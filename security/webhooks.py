"""
Webhook utilities for verifying and processing VAPI webhooks.
"""

import hmac
import hashlib
import os

from fastapi import Request, HTTPException, status

async def verify_webhook_signature(request: Request) -> bool:
    """
    Verify the webhook signature from VAPI.
    
    Args:
        request: The incoming FastAPI request
        
    Returns:
        bool: True if signature is valid, False otherwise
        
    Note:
        This function requires the WEBHOOK_SECRET environment variable to be set.
    """
    # Get signature from headers
    signature = request.headers.get("x-vapi-signature")
    if not signature:
        return False
        
    # Get secret from environment
    secret = os.environ.get("WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Webhook secret not configured. Set WEBHOOK_SECRET environment variable."
        )
    
    # Read request body
    body = await request.body()
    
    # Compute expected signature
    expected_signature = hmac.new(
        secret.encode(),
        body,
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures
    return hmac.compare_digest(signature, expected_signature)
