# OAuth Scope Best Practices

- Enforce OAuth scopes for every API endpoint using dependency injection.
- Validate user permissions and scopes on every request.
- Use least-privilege principle: only grant required scopes.
- Log all scope validation failures and suspicious access attempts.
- Document all available scopes and their intended use.
