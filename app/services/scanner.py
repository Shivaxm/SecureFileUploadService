from rq import Queue
from redis import Redis
from app.core.config import settings

SCAN_QUEUE = "scan-jobs"


def get_queue() -> Queue:
    redis = Redis.from_url(settings.redis_url)
    return Queue(SCAN_QUEUE, connection=redis)


def enqueue_scan(file_id: str):
    queue = get_queue()
    queue.enqueue("app.services.scanner.perform_scan", file_id=file_id)  # type: ignore[arg-type]


def perform_scan(file_id: str) -> str:
    # TODO: fetch file, run AV scan, update state
    return f"scan for {file_id} not implemented"

