import datetime as dt
import jwt
from app.core.config import settings

ALGORITHM = settings.jwt_algorithm


def create_access_token(payload: dict) -> str:
    to_encode = payload.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(seconds=settings.jwt_expires_seconds)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None

