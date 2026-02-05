import datetime as dt
import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api import deps
from app.core.rate_limit import rate_limit_user
from app.core.security import get_password_hash
from app.db import models
from app.services.audit import log_event
from app.services.file_type_policy import validate_upload_metadata
from app.services.quota import QuotaService
from app.services.scanner import enqueue_scan
from app.services.storage import StorageClient
from app.web import templates

router = APIRouter()

_DB_DEP = Depends(deps.get_db)
_CURRENT_USER_DEP = Depends(deps.get_current_user)
_CURRENT_USER_OPTIONAL_DEP = Depends(deps.get_current_user_optional)
_DEMO_ID_DEP = Depends(deps.get_demo_id)
_RL_INIT_DEP = Depends(rate_limit_user("files_init", 10, 60))
_RL_COMPLETE_DEP = Depends(rate_limit_user("files_complete", 20, 60))
_RL_DOWNLOAD_URL_DEP = Depends(rate_limit_user("files_download_url", 30, 60))
DEMO_MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def utcnow_naive() -> dt.datetime:
    """UTC 'now' as a naive datetime (matches our DB timestamp columns)."""
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


class InitRequest(BaseModel):
    original_filename: str
    content_type: str
    checksum_sha256: str
    size_bytes: int | None = None


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


def _require_demo_started(demo_id: str | None) -> str:
    if not demo_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Start demo at POST /demo/start",
        )
    return demo_id


def _get_or_create_demo_user(db: Session, demo_id: str) -> models.User:
    demo_user = db.get(models.User, demo_id)
    if demo_user:
        return demo_user

    demo_user = models.User(
        id=demo_id,
        email=f"demo-{demo_id}@demo.local",
        hashed_password=get_password_hash(f"demo-{demo_id}"),
        role=models.UserRole.user,
    )
    db.add(demo_user)
    db.commit()
    db.refresh(demo_user)
    return demo_user


@router.post("/init", response_model=InitResponse)
async def init_upload(
    payload: InitRequest,
    request: Request,
    db: Session = _DB_DEP,
    current_user: models.User | None = _CURRENT_USER_OPTIONAL_DEP,
    demo_id: str | None = _DEMO_ID_DEP,
    _: None = _RL_INIT_DEP,
):
    from app.core.config import settings  # imported lazily to avoid cycle

    expires_at = utcnow_naive() + dt.timedelta(
        seconds=settings.upload_presign_ttl_seconds
    )
    object_key = f"{uuid.uuid4()}_{payload.original_filename.replace(' ', '_')}"
    actor_user_id = current_user.id if current_user else None
    file_demo_id: str | None = None

    if current_user:
        owner_id = current_user.id
        try:
            QuotaService(db).enforce_init(current_user.id)
        except PermissionError as err:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="quota exceeded"
            ) from err
    else:
        file_demo_id = _require_demo_started(demo_id)
        if payload.size_bytes and payload.size_bytes > DEMO_MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="demo upload size exceeds 10MB limit",
            )
        owner_id = _get_or_create_demo_user(db, file_demo_id).id

    file_obj = models.FileObject(
        owner_id=owner_id,
        bucket=settings.minio_bucket,
        object_key=object_key,
        original_filename=payload.original_filename,
        declared_content_type=payload.content_type,
        checksum_sha256=payload.checksum_sha256,
        demo_id=file_demo_id,
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
        expires_in=settings.upload_presign_ttl_seconds,
    )

    log_event(
        db,
        actor_user_id=actor_user_id,
        action="FILE_INIT",
        file_id=file_obj.id,
        request=request,
    )

    return InitResponse(
        file_id=file_obj.id,
        object_key=file_obj.object_key,
        upload_url=presigned.url,
        expires_in=settings.upload_presign_ttl_seconds,
        headers_to_include=presigned.headers,
    )


@router.post("/{file_id}/complete", response_model=CompleteResponse)
async def complete_upload(  # noqa: PLR0912, PLR0915
    file_id: str,
    request: Request,
    db: Session = _DB_DEP,
    current_user: models.User | None = _CURRENT_USER_OPTIONAL_DEP,
    demo_id: str | None = _DEMO_ID_DEP,
    _: None = _RL_COMPLETE_DEP,
):
    file_obj: models.FileObject | None = db.get(models.FileObject, file_id)
    if not file_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )
    actor_user_id = current_user.id if current_user else None
    if current_user:
        if (
            current_user.role != models.UserRole.admin
            and file_obj.owner_id != current_user.id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden"
            )
    else:
        resolved_demo_id = _require_demo_started(demo_id)
        if file_obj.demo_id != resolved_demo_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
            )
    if file_obj.state != models.FileObjectState.INITIATED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Upload not in INITIATED state",
        )
    if file_obj.upload_expires_at and file_obj.upload_expires_at < utcnow_naive():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Upload request expired"
        )

    storage = StorageClient()
    try:
        head = storage.head_object(file_obj.bucket, file_obj.object_key)
    except storage.not_found_exc as exc:
        error_code = (
            getattr(exc, "response", {}).get("Error", {}).get("Code")
            if hasattr(exc, "response")
            else None
        )
        if error_code in {"404", "NoSuchKey", "NotFound"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Object not uploaded"
            ) from exc
        raise

    file_obj.size_bytes = head.get("ContentLength")
    if (
        file_obj.demo_id
        and file_obj.size_bytes
        and file_obj.size_bytes > DEMO_MAX_UPLOAD_BYTES
    ):
        file_obj.state = models.FileObjectState.QUARANTINED
        db.commit()
        log_event(
            db,
            actor_user_id=actor_user_id,
            action="UPLOAD_QUARANTINED",
            file_id=file_obj.id,
            request=request,
            metadata={
                "reason": "demo_size_limit",
                "size": file_obj.size_bytes,
                "max": DEMO_MAX_UPLOAD_BYTES,
            },
        )
        return CompleteResponse(
            state=file_obj.state, sniffed_content_type=file_obj.sniffed_content_type
        )

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
            actor_user_id=actor_user_id,
            action="UPLOAD_REJECTED",
            file_id=file_obj.id,
            request=request,
            metadata={
                "reason": "checksum_mismatch",
                "expected": file_obj.checksum_sha256,
                "got": computed,
            },
        )
        return CompleteResponse(
            state=file_obj.state, sniffed_content_type=file_obj.sniffed_content_type
        )

    file_obj.checksum_verified = True

    # Sniff content from first bytes
    sample = storage.get_object_range(
        file_obj.bucket, file_obj.object_key, byte_range="bytes=0-16383"
    )
    sniffed = None
    if sample:
        try:
            import magic

            sniffed = magic.from_buffer(sample, mime=True)
        except Exception:
            sniffed = None
    file_obj.sniffed_content_type = sniffed

    validation = validate_upload_metadata(
        original_filename=file_obj.original_filename,
        declared_content_type=file_obj.declared_content_type,
        sniffed_content_type=sniffed,
        size_bytes=file_obj.size_bytes,
        sample_bytes=sample,
        # Keep existing behavior: demo has stricter size at upload/complete,
        # regular users are still bounded during async scan.
        max_size_bytes=DEMO_MAX_UPLOAD_BYTES if file_obj.demo_id else None,
    )
    if not validation.ok:
        file_obj.state = models.FileObjectState.QUARANTINED
        db.commit()
        log_event(
            db,
            actor_user_id=actor_user_id,
            action="UPLOAD_QUARANTINED",
            file_id=file_obj.id,
            request=request,
            metadata={
                "reason": validation.reason,
                "sniffed": sniffed,
                "declared": file_obj.declared_content_type,
                **(validation.details or {}),
            },
        )
        return CompleteResponse(state=file_obj.state, sniffed_content_type=sniffed)

    file_obj.state = models.FileObjectState.SCANNING
    db.commit()
    log_event(
        db,
        actor_user_id=actor_user_id,
        action="UPLOAD_ENQUEUED",
        file_id=file_obj.id,
        request=request,
        metadata={"sniffed": sniffed, "declared": file_obj.declared_content_type},
    )
    enqueue_scan(file_obj.id)
    return CompleteResponse(state=file_obj.state, sniffed_content_type=sniffed)


@router.get("", response_model=list[FileDetail])
async def list_files(
    request: Request,
    db: Session = _DB_DEP,
    current_user: models.User | None = _CURRENT_USER_OPTIONAL_DEP,
    demo_id: str | None = _DEMO_ID_DEP,
):
    # Browser navigation to /files renders UI; API clients should use /files?format=json.
    wants_html = (
        "text/html" in request.headers.get("accept", "")
        and request.query_params.get("format") != "json"
    )
    if wants_html:
        return templates.TemplateResponse("files.html", {"request": request})

    if current_user:
        query = db.query(models.FileObject)
        if current_user.role != models.UserRole.admin:
            query = query.filter(models.FileObject.owner_id == current_user.id)
        return query.order_by(models.FileObject.created_at.desc()).all()

    resolved_demo_id = _require_demo_started(demo_id)
    return (
        db.query(models.FileObject)
        .filter(models.FileObject.demo_id == resolved_demo_id)
        .order_by(models.FileObject.created_at.desc())
        .all()
    )


@router.get("/{file_id}", response_model=FileDetail)
async def get_file(
    file_id: str,
    db: Session = _DB_DEP,
    user: models.User = _CURRENT_USER_DEP,
):
    file_obj = db.get(models.FileObject, file_id)
    if not file_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )
    if user.role != models.UserRole.admin and file_obj.owner_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return file_obj


@router.post("/{file_id}/download-url", response_model=DownloadUrlResponse)
async def download_url(
    file_id: str,
    request: Request,
    db: Session = _DB_DEP,
    current_user: models.User | None = _CURRENT_USER_OPTIONAL_DEP,
    demo_id: str | None = _DEMO_ID_DEP,
    _: None = _RL_DOWNLOAD_URL_DEP,
):
    from app.core.config import settings  # imported lazily to avoid cycle

    file_obj = db.get(models.FileObject, file_id)
    if not file_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
        )
    actor_user_id = current_user.id if current_user else None
    if current_user:
        if (
            current_user.role != models.UserRole.admin
            and file_obj.owner_id != current_user.id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden"
            )
    else:
        resolved_demo_id = _require_demo_started(demo_id)
        if file_obj.demo_id != resolved_demo_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="File not found"
            )
    if file_obj.state != models.FileObjectState.ACTIVE and (
        not current_user or current_user.role != models.UserRole.admin
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="File not available for download",
        )

    storage = StorageClient()
    url = storage.generate_presigned_get_download(
        key=file_obj.object_key,
        download_filename=file_obj.original_filename,
        response_content_type=file_obj.declared_content_type,
        expires=settings.download_presign_ttl_seconds,
    )
    log_event(
        db,
        actor_user_id=actor_user_id,
        action="DOWNLOAD_URL_ISSUED",
        file_id=file_obj.id,
        request=request,
    )
    return DownloadUrlResponse(
        download_url=url, expires_in=settings.download_presign_ttl_seconds
    )
