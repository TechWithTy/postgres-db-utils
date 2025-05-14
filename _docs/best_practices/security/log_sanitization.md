# Log Sanitization Best Practices

- Redact sensitive fields (passwords, tokens, PII) from all logs by default.
- Use a secure logger utility that enforces redaction and structured logging.
- Never log secrets or user data in plaintext.
- Log security-relevant events (auth failures, admin actions, rate limits) for audit.
- Regularly review logs for compliance and anomalies.
