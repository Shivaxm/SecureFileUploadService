import hashlib
import httpx
import pytest
from app.db.session import SessionLocal
from app.db import models


async def register_and_get_token(client, email: str = "user@example.com", password: str = "pass1234") -> str:
    await client.post("/auth/register", json={"email": email, "password": password})
    resp = await client.post("/auth/login", json={"email": email, "password": password})
    data = resp.json()
    return data["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_register_and_login(client):
    token = await register_and_get_token(client)
    assert token


@pytest.mark.asyncio
async def test_init_returns_presigned_and_row(client):
    token = await register_and_get_token(client)
    checksum = hashlib.sha256(b"hello").hexdigest()
    resp = await client.post(
        "/files/init",
        headers=auth_headers(token),
        json={
            "original_filename": "hello.txt",
            "content_type": "text/plain",
            "checksum_sha256": checksum,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "upload_url" in body
    file_id = body["file_id"]

    db = SessionLocal()
    file_obj = db.get(models.FileObject, file_id)
    assert file_obj is not None
    assert file_obj.state == models.FileObjectState.INITIATED
    db.close()


@pytest.mark.asyncio
async def test_complete_fails_if_object_not_uploaded(client):
    token = await register_and_get_token(client)
    checksum = hashlib.sha256(b"missing").hexdigest()
    init_resp = await client.post(
        "/files/init",
        headers=auth_headers(token),
        json={
            "original_filename": "missing.txt",
            "content_type": "text/plain",
            "checksum_sha256": checksum,
        },
    )
    file_id = init_resp.json()["file_id"]
    complete = await client.post(f"/files/{file_id}/complete", headers=auth_headers(token))
    assert complete.status_code == 400


@pytest.mark.asyncio
async def test_complete_rejects_checksum_mismatch(client):
    token = await register_and_get_token(client, email="mismatch@example.com")
    expected_checksum = hashlib.sha256(b"expected").hexdigest()
    init_resp = await client.post(
        "/files/init",
        headers=auth_headers(token),
        json={
            "original_filename": "mismatch.txt",
            "content_type": "text/plain",
            "checksum_sha256": expected_checksum,
        },
    )
    body = init_resp.json()
    upload_url = body["upload_url"]
    headers = body["headers_to_include"]

    async with httpx.AsyncClient() as http_client:
        res = await http_client.put(upload_url, content=b"wrong-content", headers=headers)
        assert res.status_code in {200, 204}

    complete = await client.post(f"/files/{body['file_id']}/complete", headers=auth_headers(token))
    assert complete.status_code == 200
    assert complete.json()["state"] == models.FileObjectState.REJECTED.value


@pytest.mark.asyncio
async def test_complete_quarantines_on_sniff_mismatch(client):
    token = await register_and_get_token(client, email="quarantine@example.com")
    content = b"this is plain text"
    checksum = hashlib.sha256(content).hexdigest()
    init_resp = await client.post(
        "/files/init",
        headers=auth_headers(token),
        json={
            "original_filename": "doc.pdf",
            "content_type": "application/pdf",
            "checksum_sha256": checksum,
        },
    )
    body = init_resp.json()
    upload_url = body["upload_url"]
    headers = body["headers_to_include"]

    async with httpx.AsyncClient() as http_client:
        res = await http_client.put(upload_url, content=content, headers=headers)
        assert res.status_code in {200, 204}

    complete = await client.post(f"/files/{body['file_id']}/complete", headers=auth_headers(token))
    assert complete.status_code == 200
    assert complete.json()["state"] == models.FileObjectState.QUARANTINED.value

