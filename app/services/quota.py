from sqlalchemy.orm import Session
from app.core.config import settings
from app.db import models


class QuotaService:
    def __init__(self, db: Session):
        self.db = db

    def has_space(self, user_id: str, incoming_size: int) -> bool:
        quota = self.db.query(models.Quota).filter_by(user_id=user_id).first()
        if not quota:
            quota = models.Quota(user_id=user_id, limit_bytes=settings.quota_default_bytes, used_bytes=0)
            self.db.add(quota)
            self.db.commit()
            self.db.refresh(quota)
        # TODO: compute accurate usage from files table
        return (quota.used_bytes + incoming_size) <= quota.limit_bytes

