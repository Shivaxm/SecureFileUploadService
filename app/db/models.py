import uuid
import enum
import datetime as dt
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Boolean,
    BigInteger,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.dialects.postgresql import JSONB

Base = declarative_base()


class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"


class FileObjectState(str, enum.Enum):
    INITIATED = "INITIATED"
    UPLOADED = "UPLOADED"
    SCANNING = "SCANNING"
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)

    files = relationship("FileObject", back_populates="owner")


class FileObject(Base):
    __tablename__ = "file_objects"
    __table_args__ = (
        UniqueConstraint("bucket", "object_key", name="uq_file_object_bucket_key"),
        Index("ix_file_objects_owner_created", "owner_id", "created_at"),
    )

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    bucket = Column(String, nullable=False)
    object_key = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    declared_content_type = Column(String, nullable=False)
    checksum_sha256 = Column(String, nullable=False)
    checksum_verified = Column(Boolean, default=False, nullable=False)
    size_bytes = Column(Integer, nullable=True)
    sniffed_content_type = Column(String, nullable=True)
    state = Column(Enum(FileObjectState), default=FileObjectState.INITIATED, nullable=False)
    upload_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    owner = relationship("User", back_populates="files")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    action = Column(String, nullable=False)
    file_id = Column(String, ForeignKey("file_objects.id"), nullable=True)
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    details = Column(JSONB, nullable=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)


class UsageCounter(Base):
    __tablename__ = "usage_counters"

    user_id = Column(String, ForeignKey("users.id"), primary_key=True)
    files_count = Column(Integer, nullable=False, default=0)
    bytes_stored = Column(BigInteger, nullable=False, default=0)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

