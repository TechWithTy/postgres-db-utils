# backend/app/api/v1/endpoints/tasks.py
from fastapi import APIRouter

from app.core.db_utils.workers.models.task import CreditType, TaskConfig
from app.core.db_utils.workers.router import TaskRouter

# Create a new router for tasks
task_api_router = APIRouter()

# Initialize the TaskRouter with our new API router
task_router = TaskRouter(router=task_api_router)

# Define the configuration for a sample task
hello_task_config = TaskConfig(
    name="hello_task",
    description="A simple task that says hello.",
    required_roles=["user"],  # Requires a 'user' role
    credit_type=CreditType.AI,
    credit_cost=1,
    topic="hello-topic",
    tags=["tasks", "examples"],
)


# Register the task with the router
@task_router.add_task(config=hello_task_config)
def handle_hello_task(payload: dict):
    """The actual logic for the task, which will be executed by a worker."""
    # In a real worker, this function would be called with the payload
    print(f"Hello, {payload.get('name', 'world')}!")
