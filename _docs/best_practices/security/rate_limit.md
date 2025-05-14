# Rate Limiting Best Practices

- Apply rate limits to all sensitive and public endpoints.
- Use Valkey/Redis for distributed rate limiting and sliding window counters.
- Return HTTP 429 with `Retry-After` headers on limit breaches.
- Monitor and alert on rate limit breaches and potential abuse.
- Allow configurable limits per endpoint/user type.
