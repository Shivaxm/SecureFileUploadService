import logging
from rq import Worker
from redis import Redis
from app.core.config import settings
from app.services.scanner import SCAN_QUEUE

logger = logging.getLogger(__name__)


def main():
    conn = Redis.from_url(settings.redis_url)
    worker = Worker([SCAN_QUEUE], connection=conn)
    logger.info("Starting RQ worker for queue %s", SCAN_QUEUE)
    worker.work(with_scheduler=True)


if __name__ == "__main__":
    main()

