from sqlalchemy.orm import Session


class QuotaService:
    def __init__(self, db: Session):
        self.db = db

    def has_space(self, user_id: str, incoming_size: int) -> bool:
        # TODO: implement quotas in a later phase
        return True

