from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.db import models


def log_event(  # noqa: PLR0913
    db: Session,
    actor_user_id: str | None,
    action: str,
    file_id: str | None = None,
    request: Request | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    ip = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None
    event = models.AuditEvent(
        actor_user_id=actor_user_id,
        action=action,
        file_id=file_id,
        ip=ip,
        user_agent=user_agent,
        details=metadata,
    )
    db.add(event)
    db.commit()
