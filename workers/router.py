# backend/app/core/db_utils/workers/router.py
from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.db_utils.workers.models.task import TaskConfig
from app.core.db_utils.workers.services.credits import CreditError, CreditService
from app.core.db_utils.workers.services.pulsar import pulsar_service
from app.core.db_utils.workers.utils.auth import roles_required
from app.logging_config import get_logger
from app.models import User

logger = get_logger(__name__)


class TaskRouter:
    """A router to dynamically create and manage secure, credit-based tasks."""

    def __init__(self, router: APIRouter):
        self.router = router
        self.tasks: dict[str, TaskConfig] = {}

    def add_task(self, config: TaskConfig) -> Callable:
        """Decorator to register a function as a task and create a corresponding API endpoint."""

        def decorator(task_func: Callable) -> Callable:
            task_name = config.name
            if task_name in self.tasks:
                raise ValueError(f"Task '{task_name}' is already registered.")
            self.tasks[task_name] = config

            @self.router.post(
                f"/{task_name}",
                tags=config.tags,
                summary=config.description,
                status_code=status.HTTP_202_ACCEPTED,
            )
            async def endpoint(
                request: Request,
                user: User = Depends(roles_required(config.required_roles)),
                db: Session = Depends(get_db),
            ):
                credit_service = CreditService(db)
                payload = await request.json()
                subscription_id = payload.get("subscription_id")

                if not subscription_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="'subscription_id' is required in the request body.",
                    )

                # Determine credit cost
                credit_cost = (
                    config.credit_cost(payload)
                    if callable(config.credit_cost)
                    else config.credit_cost
                )

                # Check and deduct credits if applicable
                if config.credit_type and credit_cost > 0:
                    try:
                        credit_service.check_and_deduct_credits(
                            user=user,
                            credit_type=config.credit_type,
                            credit_cost=credit_cost,
                            subscription_id=subscription_id,
                        )
                    except CreditError as e:
                        raise HTTPException(status_code=e.status_code, detail=e.message)

                # Send task to Pulsar
                try:
                    message_data = {"user_id": str(user.id), "payload": payload}
                    pulsar_service.send_message(config.topic, message_data)
                    logger.info(f"Task '{task_name}' sent to topic '{config.topic}' for user {user.id}")
                except Exception as e:
                    # TODO: Implement refund logic for credit deduction failure
                    logger.error(f"Failed to send task '{task_name}' to Pulsar: {e}", exc_info=True)
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Failed to queue the task. Please try again.",
                    )

                return {"status": "Task accepted", "task_name": task_name}

            # Store original function for the worker to find
            endpoint.task_func = task_func
            return endpoint

        return decorator
