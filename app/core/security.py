import datetime as dt

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

ALGORITHM = settings.jwt_algorithm
pwd_context = CryptContext(
    schemes=["bcrypt_sha256"],
    deprecated="auto",
)


def create_access_token(payload: dict) -> str:
    to_encode = payload.copy()
    expire = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=settings.jwt_expires_seconds)
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except JWTError:
        return None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

