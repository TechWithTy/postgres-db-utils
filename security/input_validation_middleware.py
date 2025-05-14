"""
Input Validation and Sanitization Middleware

This middleware validates and sanitizes incoming requests for security and integrity.
- Applies to all incoming JSON and form data.
- Rejects requests with invalid or malicious input.
- Logs and blocks suspicious activity.

Follows best practices from The Pragmatic Programmer and The Clean Coder.
"""

import json
import logging
import re
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = logging.getLogger("input_validation")

# Example patterns for basic sanitization (expand as needed)
DANGEROUS_PATTERNS = [
    re.compile(r"<script.*?>", re.IGNORECASE),
    re.compile(r"(\$\{|;|`|\|)"),  # Command injection
    re.compile(r"(\\x[0-9A-Fa-f]{2})"),  # Hex encoded
]


def sanitize_value(value: str) -> str:
    """
    Removes dangerous patterns from a string.
    """
    for pattern in DANGEROUS_PATTERNS:
        value = pattern.sub("", value)
    return value


def sanitize_data(data):
    """
    Recursively sanitize all string values in a dict or list.
    """
    if isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, str):
        return sanitize_value(data)
    return data


class InputValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate and sanitize incoming requests.
    - Checks JSON and form data for dangerous content.
    - Blocks and logs malicious requests.
    """

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ):
        # Only validate POST/PUT/PATCH with body
        if request.method in {"POST", "PUT", "PATCH"}:
            content_type = request.headers.get("content-type", "")
            try:
                if "application/json" in content_type:
                    body = await request.body()
                    data = json.loads(body)
                    sanitized = sanitize_data(data)
                    # Block if any dangerous pattern found (could expand with more logic)
                    if data != sanitized:
                        logger.warning(
                            f"Blocked potentially malicious JSON input: {data}"
                        )
                        return JSONResponse(
                            {"detail": "Invalid or unsafe input detected."},
                            status_code=400,
                        )
                elif (
                    "application/x-www-form-urlencoded" in content_type
                    or "multipart/form-data" in content_type
                ):
                    form = await request.form()
                    sanitized = sanitize_data(dict(form))
                    # Check filenames for dangerous patterns (file uploads)
                    for key, value in form.items():
                        if hasattr(value, "filename"):
                            sanitized_filename = sanitize_value(value.filename)
                            if sanitized_filename != value.filename:
                                logger.warning(
                                    f"Blocked potentially malicious filename: {value.filename}",
                                    filename=value.filename,
                                    field=key,
                                )
                                return JSONResponse(
                                    {"detail": "Invalid or unsafe filename detected."},
                                    status_code=400,
                                )
                    if dict(form) != sanitized:
                        logger.warning(
                            f"Blocked potentially malicious form input: {dict(form)}"
                        )
                        return JSONResponse(
                            {"detail": "Invalid or unsafe input detected."},
                            status_code=400,
                        )
            except Exception as exc:
                logger.error(f"Input validation error: {exc}")
                return JSONResponse(
                    {"detail": "Malformed request body."}, status_code=400
                )
        response = await call_next(request)
        return response
