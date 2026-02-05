import base64
import hashlib
import hmac
import time
from collections.abc import Generator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import decode_token
from app.db import models
from app.db.session import SessionLocal

DEMO_COOKIE_NAME = "demo"
DEMO_COOKIE_MAX_AGE_SECONDS = 2 * 60 * 60


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


_DB_DEP = Depends(get_db)


def get_current_user(request: Request, db: Session = _DB_DEP) -> models.User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token"
        )
    token = auth_header.split(" ", 1)[1]
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )
    user = db.get(models.User, payload.get("sub"))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    request.state.user_id = user.id
    return user


_CURRENT_USER_DEP = Depends(get_current_user)


def require_admin(user: models.User = _CURRENT_USER_DEP) -> models.User:
    if user.role != models.UserRole.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin required"
        )
    return user


def _demo_secret() -> bytes:
    return settings.jwt_secret.encode("utf-8")


def create_demo_token(
    demo_id: str, expires_in: int = DEMO_COOKIE_MAX_AGE_SECONDS
) -> str:
    issued_at = int(time.time())
    payload = f"{demo_id}.{issued_at}.{expires_in}"
    signature = hmac.new(
        _demo_secret(),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = f"{payload}.{signature}"
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("utf-8")


def verify_demo_token(token: str) -> str | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        demo_id, issued_at_str, expires_in_str, signature = decoded.split(".", 3)
        payload = f"{demo_id}.{issued_at_str}.{expires_in_str}"
        expected = hmac.new(
            _demo_secret(),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None

        issued_at = int(issued_at_str)
        expires_in = int(expires_in_str)
        now = int(time.time())
        if now > issued_at + expires_in:
            return None
        return demo_id
    except (ValueError, TypeError, UnicodeDecodeError):
        return None


def get_demo_id(request: Request) -> str | None:
    token = request.cookies.get(DEMO_COOKIE_NAME)
    if not token:
        return None
    return verify_demo_token(token)


def get_current_user_optional(
    request: Request, db: Session = _DB_DEP
) -> models.User | None:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    payload = decode_token(token)
    if payload is None:
        return None
    user = db.get(models.User, payload.get("sub"))
    if not user:
        return None
    request.state.user_id = user.id
    return user
