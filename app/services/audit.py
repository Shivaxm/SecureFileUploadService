from sqlalchemy.orm import Session
from app.db import models


def record_audit_log(db: Session, user_id: str | None, action: str, file_id: str | None = None, metadata: str | None = None) -> None:
    # TODO: enrich metadata, async batching
    log = models.AuditLog(user_id=user_id, action=action, file_id=file_id, metadata=metadata)
    db.add(log)
    db.commit()

