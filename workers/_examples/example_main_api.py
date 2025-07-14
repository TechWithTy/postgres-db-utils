# backend/app/core/db_utils/workers/_examples/example_main_api.py

from fastapi import FastAPI

# Import the router instance that the TaskRouter is managing.
from .example_task_definitions import example_api_router

# In your main application file (e.g., app/api/main.py):
app = FastAPI(
    title="My Awesome App",
    description="This is the main FastAPI application.",
)

# Include the task router into your main application under a specific prefix.
# All tasks defined in example_task_definitions.py will now be available
# under the /api/v1/tasks/ prefix.
app.include_router(example_api_router, prefix="/api/v1/tasks", tags=["tasks"])

# The following endpoints would now be live:
# - POST /api/v1/tasks/send_marketing_email
# - POST /api/v1/tasks/summarize_text


@app.get("/")
def read_root():
    return {"message": "Welcome to the main application!"}
