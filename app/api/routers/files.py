import hashlib
import uuid
import datetime as dt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api import deps
from app.db import models
from app.services.storage import StorageClient
from app.services.audit import log_event
from app.services.scanner import enqueue_scan, ALLOWED_CONTENT_TYPES

router = APIRouter()


class InitRequest(BaseModel):
    original_filename: str
    content_type: str
    checksum_sha256: str


class InitResponse(BaseModel):
    file_id: str
    object_key: str
    upload_url: str
    expires_in: int
    headers_to_include: dict[str, str]


class CompleteResponse(BaseModel):
    state: models.FileObjectState
    sniffed_content_type: str | None


class FileDetail(BaseModel):
    id: str
    owner_id: str
    bucket: str
    object_key: str
    original_filename: str
    declared_content_type: str
    sniffed_content_type: str | None
    checksum_sha256: str
    checksum_verified: bool
    size_bytes: int | None
    state: models.FileObjectState
    created_at: dt.datetime
    updated_at: dt.datetime | None

    class Config:
        orm_mode = True


class DownloadUrlResponse(BaseModel):
    download_url: str
    expires_in: int


@router.post("/init", response_model=InitResponse)
async def init_upload(
    payload: InitRequest,
    request: Request,
    db: Session = Depends(deps.get_db),
    user: models.User = Depends(deps.get_current_user),
):
    expires_at = dt.datetime.utcnow() + dt.timedelta(minutes=15)
    object_key = f"{uuid.uuid4()}_{payload.original_filename.replace(' ', '_')}"

    from app.core.config import settings  # imported lazily to avoid cycle

    file_obj = models.FileObject(
        owner_id=user.id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        original_filename=payload.original_filename,
        declared_content_type=payload.content_type,
        checksum_sha256=payload.checksum_sha256,
        state=models.FileObjectState.INITIATED,
        upload_expires_at=expires_at,
    )

    db.add(file_obj)
    db.commit()
    db.refresh(file_obj)

    storage = StorageClient()
    presigned = storage.generate_presigned_put(
        key=file_obj.object_key,
        content_type=payload.content_type,
        expires_in=15 * 60,
        extra_metadata={
            "checksum-sha256": payload.checksum_sha256,
            "owner-id": user.id,
        },
    )

    log_event(db, actor_user_id=user.id, action="FILE_INIT", file_id=file_obj.id, request=request)

    return InitResponse(
        file_id=file_obj.id,
        object_key=file_obj.object_key,
        upload_url=presigned.url,
        expires_in=15 * 60,
        headers_to_include=presigned.headers,
    )


@router.post("/{file_id}/complete", response_model=CompleteResponse)
async def complete_upload(
    file_id: str,
    request: Request,
    db: Session = Depends(deps.get_db),
    user: models.User = Depends(deps.get_current_user),
):
    file_obj: models.FileObject | None = db.get(models.FileObject, file_id)
    if not file_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if user.role != models.UserRole.admin and file_obj.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    if file_obj.state != models.FileObjectState.INITIATED:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload not in INITIATED state")
    if file_obj.upload_expires_at and file_obj.upload_expires_at < dt.datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Upload request expired")

    storage = StorageClient()
    try:
        head = storage.head_object(file_obj.bucket, file_obj.object_key)
    except storage.not_found_exc as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
        if error_code in {"404", "NoSuchKey", "NotFound"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Object not uploaded")
        raise

    file_obj.size_bytes = head.get("ContentLength")

    # Compute checksum
    hasher = hashlib.sha256()
    for chunk in storage.iter_object(file_obj.bucket, file_obj.object_key):
        hasher.update(chunk)
    computed = hasher.hexdigest()
    if computed != file_obj.checksum_sha256:
        file_obj.state = models.FileObjectState.REJECTED
        file_obj.checksum_verified = False
        db.commit()
        log_event(
            db,
            actor_user_id=user.id,
            action="UPLOAD_REJECTED",
            file_id=file_obj.id,
            request=request,
            metadata={"reason": "checksum_mismatch", "expected": file_obj.checksum_sha256, "got": computed},
        )
        return CompleteResponse(state=file_obj.state, sniffed_content_type=file_obj.sniffed_content_type)

    file_obj.checksum_verified = True

    # Sniff content from first bytes
    sample = storage.get_object_range(file_obj.bucket, file_obj.object_key, byte_range="bytes=0-16383")
    sniffed = None
    if sample:
        try:
            import magic

            sniffed = magic.from_buffer(sample, mime=True)
        except Exception:
            sniffed = None
    file_obj.sniffed_content_type = sniffed

    if sniffed and sniffed.split(";")[0] != file_obj.declared_content_type.split(";")[0]:
        file_obj.state = models.FileObjectState.QUARANTINED
        db.commit()
        log_event(
            db,
            actor_user_id=user.id,
            action="UPLOAD_QUARANTINED",
            file_id=file_obj.id,
            request=request,
            metadata={"sniffed": sniffed, "declared": file_obj.declared_content_type},
        )
        return CompleteResponse(state=file_obj.state, sniffed_content_type=sniffed)

    if sniffed and sniffed.split(";")[0] not in ALLOWED_CONTENT_TYPES:
        file_obj.state = models.FileObjectState.QUARANTINED
        db.commit()
        log_event(
            db,
            actor_user_id=user.id,
            action="UPLOAD_QUARANTINED",
            file_id=file_obj.id,
            request=request,
            metadata={"reason": "disallowed_type", "sniffed": sniffed, "declared": file_obj.declared_content_type},
        )
        return CompleteResponse(state=file_obj.state, sniffed_content_type=sniffed)

    file_obj.state = models.FileObjectState.SCANNING
    db.commit()
    log_event(
        db,
        actor_user_id=user.id,
        action="UPLOAD_ENQUEUED",
        file_id=file_obj.id,
        request=request,
        metadata={"sniffed": sniffed, "declared": file_obj.declared_content_type},
    )
    enqueue_scan(file_obj.id)
    return CompleteResponse(state=file_obj.state, sniffed_content_type=sniffed)


@router.get("/{file_id}", response_model=FileDetail)
async def get_file(
    file_id: str,
    db: Session = Depends(deps.get_db),
    user: models.User = Depends(deps.get_current_user),
):
    file_obj = db.get(models.FileObject, file_id)
    if not file_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if user.role != models.UserRole.admin and file_obj.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return file_obj


@router.post("/{file_id}/download-url", response_model=DownloadUrlResponse)
async def download_url(
    file_id: str,
    request: Request,
    db: Session = Depends(deps.get_db),
    user: models.User = Depends(deps.get_current_user),
):
    file_obj = db.get(models.FileObject, file_id)
    if not file_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    if user.role != models.UserRole.admin and file_obj.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    if file_obj.state != models.FileObjectState.ACTIVE and user.role != models.UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="File not available for download")

    storage = StorageClient()
    url = storage.generate_presigned_get(file_obj.object_key, expires=300)
    log_event(db, actor_user_id=user.id, action="DOWNLOAD_URL_ISSUED", file_id=file_obj.id, request=request)
    return DownloadUrlResponse(download_url=url, expires_in=300)

