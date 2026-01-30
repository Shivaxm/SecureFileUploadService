import datetime as dt

from sqlalchemy.orm import Session

from app.db import models

MAX_FILES = 200
MAX_BYTES = 2_000_000_000


def utcnow_naive() -> dt.datetime:
    """UTC 'now' as a naive datetime (matches our DB timestamp columns)."""
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class QuotaService:
    def __init__(self, db: Session):
        self.db = db

    def _get_counter(self, user_id: str) -> models.UsageCounter:
        counter = self.db.get(models.UsageCounter, user_id)
        if not counter:
            counter = models.UsageCounter(
                user_id=user_id,
                files_count=0,
                bytes_stored=0,
                updated_at=utcnow_naive(),
            )
            self.db.add(counter)
            self.db.commit()
            self.db.refresh(counter)
        return counter

    def enforce_init(self, user_id: str) -> None:
        counter = self._get_counter(user_id)
        if counter.files_count >= MAX_FILES:
            raise PermissionError("quota exceeded")
        # bytes enforcement deferred until file is active

    def increment_on_active(self, user_id: str, file_size: int | None) -> None:
        counter = self._get_counter(user_id)
        new_files = counter.files_count + 1
        new_bytes = counter.bytes_stored + (file_size or 0)
        if new_files > MAX_FILES or new_bytes > MAX_BYTES:
            raise PermissionError("quota exceeded")
        counter.files_count = new_files
        counter.bytes_stored = new_bytes
        counter.updated_at = utcnow_naive()
        self.db.commit()

    def decrement_on_delete(self, user_id: str, file_size: int | None) -> None:
        counter = self._get_counter(user_id)
        counter.files_count = max(0, counter.files_count - 1)
        counter.bytes_stored = max(0, counter.bytes_stored - (file_size or 0))
        counter.updated_at = utcnow_naive()
        self.db.commit()

