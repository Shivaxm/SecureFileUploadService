from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.api import deps
from app.core.rbac import authorize_object
from app.db import models
from app.services.storage import StorageClient
from app.services.state import FileState
from app.services.audit import record_audit_log
from app.services.quota import QuotaService

router = APIRouter()


class PresignUploadRequest(BaseModel):
    filename: str
    content_type: str
    size_bytes: int


@router.post("/presign-upload")
async def presign_upload(
    payload: PresignUploadRequest,
    db: Session = Depends(deps.get_db),
    user: models.User = Depends(deps.get_current_user),
):
    # TODO: enforce quota, rate limits, virus scan policies
    quota = QuotaService(db)
    if not quota.has_space(user_id=user.id, incoming_size=payload.size_bytes):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Quota exceeded")

    storage = StorageClient()
    upload = storage.generate_presigned_put(payload.filename, payload.content_type)
    # TODO: create File record with PENDING_UPLOAD state
    record_audit_log(db, user_id=user.id, action="presign_upload_requested")
    return {"upload_url": upload.url, "headers": upload.headers}


@router.get("/{file_id}/presign-download")
async def presign_download(
    file_id: str,
    db: Session = Depends(deps.get_db),
    user: models.User = Depends(deps.get_current_user),
):
    file_obj = db.get(models.File, file_id)
    if not file_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
    authorize_object(user, file_obj)
    storage = StorageClient()
    download_url = storage.generate_presigned_get(file_obj.storage_key)
    record_audit_log(db, user_id=user.id, action="presign_download_requested")
    return {"download_url": download_url, "state": file_obj.state or FileState.PENDING_UPLOAD}

