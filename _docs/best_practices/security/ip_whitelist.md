# IP Whitelist Best Practices

- Restrict access to sensitive/admin endpoints by IP address.
- Store whitelisted IPs in environment variables or a secure config store.
- Support dynamic reload of IP whitelist without server restart.
- Log all access denials and suspicious IP access attempts.
- Provide clear error messages for denied requests (HTTP 403).
- Regularly audit and update the whitelist for compliance.
