# Credits System Best Practices

This guide documents production-grade usage of credit-based access control for FastAPI endpoints using `call_function_with_credits`. It covers both Supabase and Postgres backends, real enforcement, and best practices for robust, auditable credit management.

---

## Overview
- Enforce per-endpoint credit requirements for AI, Leads, SkipTrace, or other metered APIs.
- Supports both Supabase and Postgres (SQLAlchemy) backends.
- Handles authentication, admin override, atomic deduction, and audit logging.
- Returns 402/400/404/500 errors for quota, input, or backend issues.

---

## Usage Pattern

**Wrap your endpoint logic using `call_function_with_credits` as a dependency or callable:**

```python
from fastapi import APIRouter, Request, Depends
from app.core.db_utils.credits.credits import call_function_with_credits

router = APIRouter()

async def my_endpoint_logic(request: Request, user):
    # Your actual endpoint logic here
    return {"message": "Success!"}

@router.post("/ai-task")
async def ai_task(
    request: Request,
    response=Depends(lambda request=Depends(), db=Depends(), user=Depends():
        call_function_with_credits(
            func=my_endpoint_logic,
            request=request,
            credit_type="ai",  # or "leads", "skiptrace"
            db=db,
            current_user=user,
            credit_amount=2  # or dynamic
        )
    )
):
    return response
```
- Ensure the request body includes `subscription_id` for credit lookup.
- You can wrap this in a custom dependency or decorator for DRYness.

---

## Best Practices
- Always validate the credit type and amount.
- Use `call_function_with_credits` for any endpoint that requires credit enforcement.
- Handle exceptions and rollbacks as shown in the implementation.
- For async endpoints, ensure all DB/session access is non-blocking.
- Admins can override credit amount by passing `credit_amount` in the request body.
- All errors are returned as HTTPException with clear details (quota, input, backend).

---

## Troubleshooting & Extension
- If you see 400/404/402 errors, check that `subscription_id` is present and credits exist.
- For custom credit logic, extend or wrap `call_function_with_credits`.
- For refunds on error, implement logic in the exception block after the main call.

---

*Keep this as the single source of truth for credit enforcement patterns in your project. Last updated: 2025-05-13.*

---

## 1. Always Estimate Before Consuming
- Use estimation functions (e.g., `estimate_mls_credits`, `estimate_phone_credits`, `estimate_theharvester_credits`) to predict credit cost before running resource-intensive operations.
- Show users the estimated credit cost in the UI or API response before executing the task.

## 2. Defensive Coding
- Always default to a minimum of 1 credit for unknown or edge cases.
- Use `max(..., 1)` logic to avoid zero or negative credits.
- Handle exceptions gracefully in estimation functions to prevent blocking user requests.

## 3. Atomic Credit Deduction
- Deduct credits in a single, atomic transaction before starting the operation.
- Roll back or refund credits only if the operation fails due to a system error (not user input).
- Use database transactions or distributed locks if needed for concurrency.

## 4. Transparent Feedback
- Log all credit deductions and estimation events for auditing.
- Return remaining credits and usage details in API responses.
- Provide clear error messages when users lack sufficient credits.

## 5. Security & Abuse Prevention
- Rate limit endpoints that consume credits to prevent rapid depletion by malicious actors.
- Monitor for anomalous usage patterns and alert on spikes.
- Never allow negative balances; always enforce a hard floor of zero.

## 6. Testing & Monitoring
- Write unit tests for all estimation and deduction logic, including edge cases.
- Track metrics on average credits consumed per endpoint and user.
- Alert on estimation/deduction mismatches and failed transactions.

## 7. API/UX Design
- Surface estimated and actual credits consumed in API responses and dashboards.
- Allow users to preview cost before committing to large or expensive tasks.
- Document all credit-related fields in your OpenAPI schema and docs.

---

## Example: Credit Estimation and Deduction Flow

```python
from app.core.db_utils.credits.credits_estimation import estimate_mls_credits
from app.core.db_utils.credits.credits import deduct_credits

# Estimate credits needed
credits_needed = estimate_mls_credits(request)

# Check user balance (pseudo-code)
if user.credits < credits_needed:
    raise HTTPException(status_code=402, detail="Insufficient credits")

# Deduct credits atomically
success = deduct_credits(user_id=user.id, amount=credits_needed)
if not success:
    raise HTTPException(status_code=500, detail="Failed to deduct credits")

# Proceed with the operation
result = run_resource_intensive_task(request)
```

---

*Last updated: 2025-05-13*
