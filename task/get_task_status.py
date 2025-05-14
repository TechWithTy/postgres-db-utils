import logging
from typing import Any

from celery.result import AsyncResult

from app.core.valkey_core.client import client as ValkeyClient


def get_task_status(task_id: str) -> Any:
    """
    Fetch the status and result of a Celery task by its task_id.
    Returns:
        - status: PENDING, STARTED, SUCCESS, FAILURE, etc.
        - result: The result of the task if successful, or error info if failed.
    """
    task_result = AsyncResult(task_id)
    response = {"task_id": task_id, "status": task_result.status}
    if task_result.status == "SUCCESS":
        response["result"] = task_result.result
    elif task_result.status == "FAILURE":
        # Only return sanitized error info
        response["error"] = str(task_result.result)
    if task_result.status in ("PENDING", "STARTED"):
        response["result"] = None
    return response

async def get_pulsar_task_status(task_id: str) -> dict[str, Any]:
    """
    Fetch the status and result of a Pulsar-based task by its task_id.

    Looks up Redis for keys:
      - pulsar:task:{task_id}:status
      - pulsar:task:{task_id}:result
    Returns:
        - status: PENDING, STARTED, SUCCESS, FAILURE, etc.
        - result: The result of the task if successful, or error info if failed.
    """
    valkey = ValkeyClient()
    status_key = f"pulsar:task:{task_id}:status"
    result_key = f"pulsar:task:{task_id}:result"
    response = {"task_id": task_id, "status": "PENDING", "result": None}
    try:
        status = await valkey.get(status_key)
        if status is not None:
            status = status.decode() if isinstance(status, bytes) else str(status)
            response["status"] = status
        result = await valkey.get(result_key)
        if result is not None:
            # Try to decode result as utf-8, fallback to str
            try:
                result = result.decode() if isinstance(result, bytes) else result
            except Exception:
                result = str(result)
            if response["status"] == "SUCCESS":
                response["result"] = result
            elif response["status"] == "FAILURE":
                response["error"] = result
        elif response["status"] in ("PENDING", "STARTED"):
            response["result"] = None
    except Exception as e:
        logging.exception(f"Error fetching Pulsar task status for {task_id}: {e}")
        response["status"] = "ERROR"
        response["error"] = str(e)
    return response
