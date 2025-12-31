from fastapi import HTTPException, status
from app.db import models


def authorize_object(user: models.User, obj: object) -> None:
    # TODO: implement object-level permissions and RBAC
    if getattr(obj, "user_id", None) not in {None, user.id} and user.role != models.UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

