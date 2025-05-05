# Security Best Practices

## Token Management
- Always set reasonable expiration (default: 30m)
- Store tokens securely (HttpOnly cookies)
- Implement refresh token rotation

## Password Security
- Minimum 12 character length enforced
- Reject common passwords
- Use zxcvbn for complexity scoring
