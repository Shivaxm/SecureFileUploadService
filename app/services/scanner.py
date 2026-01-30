from redis import Redis
from rq import Queue
from rq.job import Retry
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.db.session import SessionLocal
from app.services.audit import log_event
from app.services.quota import QuotaService
from app.services.storage import StorageClient

SCAN_QUEUE = "scan"
MAX_SIZE_BYTES = 50 * 1024 * 1024
ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "application/pdf",
    "image/png",
    "image/jpeg",
}


def get_queue() -> Queue:
    redis = Redis.from_url(settings.redis_url)
    return Queue(SCAN_QUEUE, connection=redis)


def enqueue_scan(file_id: str):
    queue = get_queue()
    queue.enqueue(
        "app.services.scanner.scan_file",
        file_id=file_id,
        retry=Retry(max=3, interval=[10, 30, 60]),
    )


def scan_file(file_id: str) -> str:  # noqa: PLR0911, PLR0912
    db: Session = SessionLocal()
    try:
        file_obj: models.FileObject | None = db.get(models.FileObject, file_id)
        if not file_obj:
            return "missing"
        if file_obj.state != models.FileObjectState.SCANNING:
            return "skip"

        storage = StorageClient()
        head = storage.head_object(file_obj.bucket, file_obj.object_key)
        file_obj.size_bytes = head.get("ContentLength")

        sample = storage.get_object_range(
            file_obj.bucket, file_obj.object_key, byte_range="bytes=0-16383"
        )
        sniffed = file_obj.sniffed_content_type
        if sample:
            try:
                import magic

                sniffed = magic.from_buffer(sample, mime=True)
            except Exception:
                pass
        file_obj.sniffed_content_type = sniffed

        # Rules
        if sniffed is None:
            file_obj.state = models.FileObjectState.QUARANTINED
            db.commit()
            log_event(
                db,
                actor_user_id=file_obj.owner_id,
                action="SCAN_QUARANTINED",
                file_id=file_obj.id,
                metadata={"reason": "sniff_missing"},
            )
            return "quarantined"

        if file_obj.size_bytes and file_obj.size_bytes > MAX_SIZE_BYTES:
            file_obj.state = models.FileObjectState.QUARANTINED
            db.commit()
            log_event(
                db,
                actor_user_id=file_obj.owner_id,
                action="SCAN_QUARANTINED",
                file_id=file_obj.id,
                metadata={"reason": "too_large", "size": file_obj.size_bytes},
            )
            return "quarantined"

        declared_ok = (
            file_obj.declared_content_type.split(";")[0] in ALLOWED_CONTENT_TYPES
        )
        sniff_ok = sniffed.split(";")[0] in ALLOWED_CONTENT_TYPES

        if declared_ok and sniff_ok:
            file_obj.state = models.FileObjectState.ACTIVE
            try:
                QuotaService(db).increment_on_active(
                    file_obj.owner_id, file_obj.size_bytes or 0
                )
                db.commit()
                log_event(
                    db,
                    actor_user_id=file_obj.owner_id,
                    action="SCAN_PASS",
                    file_id=file_obj.id,
                    metadata={"sniffed": sniffed},
                )
                return "active"
            except PermissionError:
                file_obj.state = models.FileObjectState.QUARANTINED
                db.commit()
                log_event(
                    db,
                    actor_user_id=file_obj.owner_id,
                    action="SCAN_QUARANTINED",
                    file_id=file_obj.id,
                    metadata={"reason": "quota_exceeded"},
                )
                return "quarantined"

        file_obj.state = models.FileObjectState.QUARANTINED
        db.commit()
        log_event(
            db,
            actor_user_id=file_obj.owner_id,
            action="SCAN_QUARANTINED",
            file_id=file_obj.id,
            metadata={
                "reason": "disallowed_type",
                "sniffed": sniffed,
                "declared": file_obj.declared_content_type,
            },
        )
        return "quarantined"

    except Exception as exc:  # noqa: BLE001
        log_event(
            db,
            actor_user_id=None,
            action="SCAN_FAIL",
            file_id=file_id,
            metadata={"error": str(exc)},
        )
        raise
    finally:
        db.close()
