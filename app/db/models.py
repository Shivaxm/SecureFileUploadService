import uuid
import enum
import datetime as dt
from sqlalchemy import Column, String, DateTime, Enum, Integer, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)

    files = relationship("File", back_populates="owner")


class FileState(str, enum.Enum):
    pending_upload = "PENDING_UPLOAD"
    uploading = "UPLOADING"
    scanning = "SCANNING"
    available = "AVAILABLE"
    quarantined = "QUARANTINED"
    deleted = "DELETED"


class File(Base):
    __tablename__ = "files"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    filename = Column(String, nullable=False)
    storage_key = Column(String, nullable=False)
    checksum = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    state = Column(Enum(FileState), default=FileState.pending_upload, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    owner = relationship("User", back_populates="files")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    file_id = Column(String, ForeignKey("files.id"), nullable=True)
    metadata = Column(String, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)


class Quota(Base):
    __tablename__ = "quotas"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False)
    limit_bytes = Column(Integer, nullable=False)
    used_bytes = Column(Integer, default=0, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    user = relationship("User")

