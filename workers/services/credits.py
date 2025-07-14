# backend/app/core/db_utils/workers/services/credits.py
from sqlalchemy.orm import Session

from app.logging_config import get_logger
from app.models import User
from app.models._data.user.billing.credit_models import (
    AICredits,
    CreditType,
    LeadCredits,
    SkipTraceCredits,
)

logger = get_logger(__name__)


class CreditError(Exception):
    """Custom exception for credit-related errors."""

    def __init__(self, message: str, status_code: int = 402):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class CreditService:
    """Service for handling credit management."""

    def __init__(self, db: Session):
        self._db = db
        self._credit_model_map = {
            CreditType.AI: AICredits,
            CreditType.LEADS: LeadCredits,
            CreditType.SKIPTRACE: SkipTraceCredits,
        }

    def check_and_deduct_credits(
        self,
        user: User,
        credit_type: CreditType,
        credit_cost: int,
        subscription_id: str,
    ) -> None:
        """Check for sufficient credits and deduct them atomically."""
        if credit_cost == 0:
            return

        # Admin users are exempt from credit deductions
        if user.is_superuser or user.is_staff:
            logger.info(f"Admin user {user.id} bypassed credit check for {credit_cost} {credit_type.value} credits.")
            return

        credit_model = self._credit_model_map.get(credit_type)
        if not credit_model:
            raise CreditError(f"Invalid credit type: {credit_type}", status_code=400)

        try:
            credits_row = (
                self._db.query(credit_model)
                .filter_by(subscriptionid=subscription_id)
                .with_for_update()
                .first()
            )

            if not credits_row:
                raise CreditError(f"No credits found for this subscription ({credit_type.value}).", status_code=404)

            available_credits = credits_row.allotted - credits_row.used
            if available_credits < credit_cost:
                raise CreditError(
                    f"Insufficient {credit_type.value} credits. Required: {credit_cost}, Available: {available_credits}"
                )

            credits_row.used += credit_cost
            self._db.commit()
            logger.info(f"Deducted {credit_cost} {credit_type.value} credits from user {user.id} for subscription {subscription_id}.")

        except Exception as e:
            self._db.rollback()
            logger.error(
                f"Failed to deduct credits for user {user.id}: {e}", exc_info=True
            )
            raise CreditError(f"Failed to process credit transaction: {e}", status_code=500) from e
