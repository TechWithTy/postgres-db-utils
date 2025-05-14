# Webhook Security Best Practices

- Require HMAC signatures for all incoming webhooks.
- Validate signature using a secret from environment variables.
- Reject unsigned or invalid webhooks with HTTP 401/403.
- Never process webhooks without verifying authenticity.
- Log all webhook events and signature failures.
