import pytest
import asyncio
from httpx import AsyncClient
from app.main import app


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop


@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://testserver") as c:
        yield c

