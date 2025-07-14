# backend/app/core/db_utils/workers/_examples/example_task_definitions.py

from fastapi import APIRouter

from app.core.db_utils.workers.models.task import CreditType, TaskConfig
from app.core.db_utils.workers.router import TaskRouter

# 1. Create a standard FastAPI APIRouter. This will be managed by the TaskRouter.
example_api_router = APIRouter()

# 2. Initialize the TaskRouter, passing it the APIRouter instance.
#    This can be a shared instance across your application.
task_router = TaskRouter(router=example_api_router)


# 3. Define the configuration for a new task using the TaskConfig model.
#    This object declaratively defines the endpoint's behavior.
send_email_config = TaskConfig(
    name="send_marketing_email",
    description="Queues a marketing email to be sent to a contact.",
    tags=["marketing", "emails"],
    # 4. Define RBAC: only users with 'marketing' or 'admin' roles can access.
    required_roles=["marketing"],
    # 5. Define Credit Cost: each call costs 1 'AI' credit.
    credit_type=CreditType.AI,
    credit_cost=1,
    # 6. Define Pulsar Topic: the task message will be sent here.
    topic="email-marketing-topic",
)


# 7. Register the task using the @task_router.add_task() decorator.
#    The decorator uses the config to create a secure FastAPI endpoint.
@task_router.add_task(config=send_email_config)
def process_email_task(payload: dict):
    """
    This function's content is NOT executed by the API.
    It serves as a placeholder for the logic that your Pulsar worker will execute
    when it consumes a message from the 'email-marketing-topic'.
    """
    # --- Worker Logic Example ---
    # contact_id = payload.get("contact_id")
    # template = payload.get("email_template")
    # print(f"WORKER: Sending email template {template} to contact {contact_id}.")
    # --- End Worker Logic ---
    pass


# You can add more tasks to the same router.
summarize_text_config = TaskConfig(
    name="summarize_text",
    description="Summarizes a block of text using an AI model.",
    tags=["ai", "text"],
    required_roles=["user"],
    credit_type=CreditType.AI,
    # Example of dynamic credit cost: 1 credit per 1000 characters.
    credit_cost=lambda payload: 1 + len(payload.get("text", "")) // 1000,
    topic="text-summarization-topic",
)


@task_router.add_task(config=summarize_text_config)
def process_summarization_task(payload: dict):
    """Placeholder for the text summarization worker logic."""
    pass
