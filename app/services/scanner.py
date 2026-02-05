import io
import zipfile

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
ZIP_MIME = "application/zip"
OCTET_STREAM_MIME = "application/octet-stream"
OFFICE_ZIP_MIME_TYPES: dict[str, set[str]] = {
    # Office Open XML formats are ZIP containers. We validate structure before marking ACTIVE.
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
        "[Content_Types].xml",
        "word/document.xml",
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
        "[Content_Types].xml",
        "xl/workbook.xml",
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
        "[Content_Types].xml",
        "ppt/presentation.xml",
    },
}
ALLOWED_CONTENT_TYPES = {
    "text/plain",
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    # Allow common recruiter docs; validated as ZIP containers if sniffed as application/zip.
    *OFFICE_ZIP_MIME_TYPES.keys(),
}


def _is_valid_office_zip(
    storage: StorageClient, bucket: str, key: str, declared_mime: str
) -> bool:
    required = OFFICE_ZIP_MIME_TYPES.get(declared_mime)
    if not required:
        return False

    # MAX_SIZE_BYTES bounds memory usage here.
    data = io.BytesIO()
    for chunk in storage.iter_object(bucket, key):
        data.write(chunk)
        if data.tell() > MAX_SIZE_BYTES:
            return False
    data.seek(0)

    try:
        with zipfile.ZipFile(data) as zf:
            names = set(zf.namelist())
            return required.issubset(names)
    except zipfile.BadZipFile:
        return False


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


def scan_file(file_id: str) -> str:  # noqa: PLR0911, PLR0912, PLR0915
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

        declared_base = file_obj.declared_content_type.split(";")[0]
        sniff_base = sniffed.split(";")[0]

        is_office_declared = declared_base in OFFICE_ZIP_MIME_TYPES
        should_validate_office = is_office_declared and sniff_base in {
            ZIP_MIME,
            OCTET_STREAM_MIME,
        }
        if should_validate_office and not _is_valid_office_zip(
            storage, file_obj.bucket, file_obj.object_key, declared_base
        ):
            file_obj.state = models.FileObjectState.QUARANTINED
            db.commit()
            log_event(
                db,
                actor_user_id=file_obj.owner_id,
                action="SCAN_QUARANTINED",
                file_id=file_obj.id,
                metadata={"reason": "office_zip_invalid", "declared": declared_base},
            )
            return "quarantined"

        declared_ok = declared_base in ALLOWED_CONTENT_TYPES
        sniff_ok = sniff_base in ALLOWED_CONTENT_TYPES or should_validate_office

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
