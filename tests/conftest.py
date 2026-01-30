import asyncio

import boto3
import pytest
import pytest_asyncio
import redis
from httpx import AsyncClient
from sqlalchemy import text

from app.core.config import settings
from app.db.models import Base
from app.db.session import engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture(scope="function", autouse=True)
def clean_db():
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE audit_events RESTART IDENTITY CASCADE"))
        conn.execute(text("TRUNCATE TABLE file_objects RESTART IDENTITY CASCADE"))
        conn.execute(text("TRUNCATE TABLE users RESTART IDENTITY CASCADE"))
        conn.execute(text("TRUNCATE TABLE usage_counters RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture(scope="session", autouse=True)
def ensure_bucket():
    client = boto3.client(
        "s3",
        endpoint_url=settings.minio_endpoint,
        aws_access_key_id=settings.minio_access_key,
        aws_secret_access_key=settings.minio_secret_key,
    )
    try:
        client.head_bucket(Bucket=settings.minio_bucket)
    except Exception:
        client.create_bucket(Bucket=settings.minio_bucket)
    yield


@pytest.fixture(autouse=True)
def flush_redis():
    r = redis.Redis.from_url(settings.redis_url)
    r.flushdb()
    yield


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://testserver") as c:
        yield c

