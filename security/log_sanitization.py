"""
Log Sanitization Utility

- Provides a structlog-based logger that automatically redacts sensitive values from log messages.
- Optionally prints logs to stdout if enabled (for local/dev debugging).
- Follows best practices for secure logging (no secrets, passwords, tokens, PII in logs).

Usage:
    from app.core.db_utils.security.log_sanitization import get_secure_logger
    logger = get_secure_logger("my.module")
    logger.info("User login", email="user@example.com", password="hunter2")
    # Output: User login | email="[REDACTED]" | password="[REDACTED]"
"""

import os
import re
from typing import Any

import structlog
from opentelemetry.trace import get_current_span

# list of sensitive keys (case-insensitive)
SENSITIVE_KEYS = [
    # Authentication credentials
    "password",
    "passwd",
    "secret",
    "token",
    "auth",
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session",
    # Personal identifiable information (PII)
    "email",
    "ssn",
    "social_security",
    "dob",
    "birth",
    "phone",
    "address",
    "license",
    "passport",
    "id_number",
    "account_number",
    # Financial information
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "expiry",
    "bank_account",
    "routing_number",
    "tax_id",
    "ein",
    "payment",
    # API and service keys (patterns)
    "key",
    "secret",
    "private",
    "sk_",
    "pk_",
    "api_",
    "oauth",
    "jwt",
    "salt",
    "hash",
    "signature",
    "cert",
    "certificate",
    # Healthcare information
    "health",
    "medical",
    "diagnosis",
    "treatment",
    "prescription",
    # Biometric data
    "biometric",
    "fingerprint",
    "facial",
    "dna",
    "retina",
    "voice_print",
]

# Generic patterns for sensitive keys (regex, case-insensitive)
GENERIC_SENSITIVE_PATTERNS = [
    r".*token.*",
    r".*secret.*",
    r".*key.*",
    r".*credential.*",
    r".*pass.*",
    r".*auth.*",
    r".*session.*",
    r".*ssn.*",
    r".*card.*",
    r".*account.*",
    r".*cert.*",
    r".*number.*",
    r".*id.*",
    r".*email.*",
    r".*phone.*",
    r".*address.*",
    r".*dob.*",
    r".*birth.*",
    r".*license.*",
    r".*biometric.*",
    r".*fingerprint.*",
    r".*facial.*",
    r".*dna.*",
    r".*retina.*",
    r".*voice.*",
    r".*health.*",
    r".*medical.*",
    r".*diagnosis.*",
    r".*treatment.*",
    r".*prescription.*",
]

# Allow dynamic extension of sensitive keys/patterns at runtime
EXTRA_SENSITIVE_KEYS = set()
EXTRA_SENSITIVE_PATTERNS = set()


def add_sensitive_key(key: str):
    """Add a sensitive key at runtime (exact match, case-insensitive)."""
    EXTRA_SENSITIVE_KEYS.add(key.lower())


def add_sensitive_pattern(pattern: str):
    """Add a sensitive key pattern at runtime (regex, case-insensitive)."""
    EXTRA_SENSITIVE_PATTERNS.add(pattern)


# Compile all patterns
SENSITIVE_KEY_PATTERN = re.compile(
    r"(" + r"|".join(SENSITIVE_KEYS) + r")", re.IGNORECASE
)
GENERIC_PATTERN_OBJECTS = [
    re.compile(p, re.IGNORECASE) for p in GENERIC_SENSITIVE_PATTERNS
]


def is_sensitive_key(key: str) -> bool:
    key_lower = key.lower()
    if key_lower in (k.lower() for k in SENSITIVE_KEYS):
        return True
    if key_lower in EXTRA_SENSITIVE_KEYS:
        return True
    if SENSITIVE_KEY_PATTERN.search(key):
        return True
    for pat in GENERIC_PATTERN_OBJECTS:
        if pat.match(key):
            return True
    for pat in EXTRA_SENSITIVE_PATTERNS:
        if re.compile(pat, re.IGNORECASE).match(key):
            return True
    return False


REDACTED = "[REDACTED]"


def sanitize_log_dict(log_dict: dict[str, Any]) -> dict[str, Any]:
    """
    Redact sensitive values in a log event dict.
    """
    sanitized = {}
    for k, v in log_dict.items():
        if is_sensitive_key(k):
            sanitized[k] = REDACTED
        elif isinstance(v, dict):
            sanitized[k] = sanitize_log_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_log_dict(i) if isinstance(i, dict) else i for i in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def log_sanitizer(_, __, event_dict):
    """
    structlog processor: sanitize event dict before logging and add trace context if available.
    """
    sanitized = sanitize_log_dict(event_dict)
    # Attach OpenTelemetry trace/span IDs if present
    span = get_current_span()
    if span and span.get_span_context().is_valid:
        ctx = span.get_span_context()
        sanitized["trace_id"] = format(ctx.trace_id, "032x")
        sanitized["span_id"] = format(ctx.span_id, "016x")
    return sanitized


def get_secure_logger(
    name: str = "secure_logger", print_to_stdout: bool = False, bare_print: bool = False
):
    """
    Returns a structlog logger that redacts sensitive values and attaches tracing context.
    Set print_to_stdout=True to also print logs for local/dev use.
    Set bare_print=True to use Python's built-in print (sanitized) instead of structlog.
    """
    if bare_print:

        class BarePrintLogger:
            def _print(self, level, event, **kwargs):
                # Attach OpenTelemetry trace/span IDs if present
                span = get_current_span()
                if span and span.get_span_context().is_valid:
                    ctx = span.get_span_context()
                    kwargs["trace_id"] = format(ctx.trace_id, "032x")
                    kwargs["span_id"] = format(ctx.span_id, "016x")
                sanitized = sanitize_log_dict({"event": event, **kwargs})
                print(f"[{level}] {sanitized}")

            def info(self, event, **kwargs):
                self._print("INFO", event, **kwargs)

            def warning(self, event, **kwargs):
                self._print("WARNING", event, **kwargs)

            def error(self, event, **kwargs):
                self._print("ERROR", event, **kwargs)

            def debug(self, event, **kwargs):
                self._print("DEBUG", event, **kwargs)

        return BarePrintLogger()
    else:
        processors = [
            log_sanitizer,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
        if print_to_stdout or os.environ.get("LOG_STDOUT") == "1":
            processors.insert(0, structlog.dev.ConsoleRenderer())
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(20),
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
        return structlog.get_logger(name)


def log_endpoint_event(event_name: str):
    """
    Decorator for DRY endpoint logging using the secure logger.
    Logs the event name, arguments, and keyword arguments (with sensitive data redacted).
    Supports async FastAPI endpoints.
    """
    from functools import wraps
    import inspect

    logger = get_secure_logger()

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Optionally, filter or transform args/kwargs here if needed
            logger.info(f"{event_name} called", args=args, kwargs=kwargs)
            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            return func(*args, **kwargs)

        return wrapper

    return decorator


# Usage:
#   from app.api.utils.security.log_sanitization import get_secure_logger, add_sensitive_key, add_sensitive_pattern
#   logger = get_secure_logger('my.module', bare_print=True)
#   logger.info('Sensitive event', password='hunter2', custom_field='secret')
#   add_sensitive_key('custom_field')
#   add_sensitive_pattern(r'.*recovery.*')
