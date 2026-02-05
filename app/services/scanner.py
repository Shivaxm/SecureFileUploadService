import io
import zipfile
from pathlib import Path

from redis import Redis
from rq import Queue
from rq.job import Retry
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.db.session import SessionLocal
from app.services.audit import log_event
from app.services.file_type_policy import validate_upload_metadata
from app.services.quota import QuotaService
from app.services.storage import StorageClient

SCAN_QUEUE = "scan"
MAX_SIZE_BYTES = 50 * 1024 * 1024
OFFICE_REQUIRED_ZIP_ENTRIES: dict[str, tuple[str, ...]] = {
    ".docx": ("[Content_Types].xml", "word/document.xml"),
    ".xlsx": ("[Content_Types].xml", "xl/workbook.xml"),
    ".pptx": ("[Content_Types].xml", "ppt/presentation.xml"),
}


def _has_required_office_entries(
    storage: StorageClient, bucket: str, key: str, extension: str
) -> bool:
    required = OFFICE_REQUIRED_ZIP_ENTRIES.get(extension)
    if not required:
        return True

    payload = io.BytesIO()
    for chunk in storage.iter_object(bucket, key):
        payload.write(chunk)
        if payload.tell() > MAX_SIZE_BYTES:
            return False
    payload.seek(0)

    try:
        with zipfile.ZipFile(payload) as archive:
            names = set(archive.namelist())
            return set(required).issubset(names)
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

        validation = validate_upload_metadata(
            original_filename=file_obj.original_filename,
            declared_content_type=file_obj.declared_content_type,
            sniffed_content_type=sniffed,
            size_bytes=file_obj.size_bytes,
            sample_bytes=sample,
            max_size_bytes=MAX_SIZE_BYTES,
        )
        if validation.ok:
            extension = Path(file_obj.original_filename).suffix.lower()
            if not _has_required_office_entries(
                storage, file_obj.bucket, file_obj.object_key, extension
            ):
                file_obj.state = models.FileObjectState.QUARANTINED
                db.commit()
                log_event(
                    db,
                    actor_user_id=file_obj.owner_id,
                    action="SCAN_QUARANTINED",
                    file_id=file_obj.id,
                    metadata={"reason": "office_zip_invalid", "ext": extension},
                )
                return "quarantined"

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
                "reason": validation.reason,
                "sniffed": sniffed,
                "declared": file_obj.declared_content_type,
                **(validation.details or {}),
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
