# Production Security Checklist

## Before Deployment
- [ ] Rotate `SECRET_KEY` from defaults
- [ ] Verify Redis persistence for rate limits
- [ ] Set up Prometheus alerts for:
  - Rate limit breaches
  - Failed auth attempts

## Maintenance
- [ ] Monthly: Rotate encryption keys
- [ ] Quarterly: Review rate limit thresholds
- [ ] Annually: Audit token expiration policies
