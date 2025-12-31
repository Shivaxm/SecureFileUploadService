from fastapi import HTTPException, status
from app.db import models


def authorize_owner_or_admin(user: models.User, owner_id: str) -> None:
    if user.role != models.UserRole.admin and user.id != owner_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

