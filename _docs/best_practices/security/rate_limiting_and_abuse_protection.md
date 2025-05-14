# Rate Limiting & Abuse Protection Best Practices

- Apply Redis-backed rate limits to all sensitive endpoints (login, token creation, API calls).
- Use sliding window counters for precise rate enforcement.
- Return HTTP 429 with `Retry-After` headers on limit breaches.
- Monitor and alert on rate limit breaches and failed auth attempts.
