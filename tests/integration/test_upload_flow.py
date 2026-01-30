import hashlib
from urllib.parse import urlparse, urlunparse

import httpx
import pytest
from app.db import models
from app.db.session import SessionLocal
from app.services.scanner import scan_file

HTTP_200_OK = 200
HTTP_204_NO_CONTENT = 204
HTTP_400_BAD_REQUEST = 400
HTTP_403_FORBIDDEN = 403
HTTP_429_TOO_MANY_REQUESTS = 429


async def register_and_get_token(
    client, email: str = "user@example.com", password: str = "pass1234"
) -> str:
    await client.post("/auth/register", json={"email": email, "password": password})
    resp = await client.post("/auth/login", json={"email": email, "password": password})
    data = resp.json()
    return data["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def upload_via_presigned(url: str, headers: dict[str, str], content: bytes):
    # When tests run inside Docker, "localhost" in a presigned URL refers to the
    # container itself, not the MinIO service. Rewrite to the docker network host.
    parsed = urlparse(url)
    if parsed.hostname in {"localhost", "127.0.0.1"}:
        netloc = "minio:9000"
        if parsed.username or parsed.password:
            auth = ""
            if parsed.username:
                auth += parsed.username
            if parsed.password:
                auth += f":{parsed.password}"
            netloc = f"{auth}@{netloc}"
        parsed = parsed._replace(netloc=netloc)
        url = urlunparse(parsed)

    async with httpx.AsyncClient() as http_client:
        res = await http_client.put(url, content=content, headers=headers)
        assert res.status_code in {HTTP_200_OK, HTTP_204_NO_CONTENT}


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
    assert resp.status_code == HTTP_200_OK
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
    complete = await client.post(
        f"/files/{file_id}/complete", headers=auth_headers(token)
    )
    assert complete.status_code == HTTP_400_BAD_REQUEST


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
    await upload_via_presigned(
        body["upload_url"], body["headers_to_include"], b"wrong-content"
    )

    complete = await client.post(
        f"/files/{body['file_id']}/complete", headers=auth_headers(token)
    )
    assert complete.status_code == HTTP_200_OK
    assert complete.json()["state"] == models.FileObjectState.REJECTED.value

    download = await client.post(
        f"/files/{body['file_id']}/download-url", headers=auth_headers(token)
    )
    assert download.status_code == HTTP_403_FORBIDDEN


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
    await upload_via_presigned(body["upload_url"], body["headers_to_include"], content)

    complete = await client.post(
        f"/files/{body['file_id']}/complete", headers=auth_headers(token)
    )
    assert complete.status_code == HTTP_200_OK
    assert complete.json()["state"] == models.FileObjectState.QUARANTINED.value

    download = await client.post(
        f"/files/{body['file_id']}/download-url", headers=auth_headers(token)
    )
    assert download.status_code == HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_happy_path_scan_and_download(client):
    token = await register_and_get_token(client, email="happy@example.com")
    content = b"valid plain text"
    checksum = hashlib.sha256(content).hexdigest()
    init_resp = await client.post(
        "/files/init",
        headers=auth_headers(token),
        json={
            "original_filename": "note.txt",
            "content_type": "text/plain",
            "checksum_sha256": checksum,
        },
    )
    init_body = init_resp.json()
    await upload_via_presigned(
        init_body["upload_url"], init_body["headers_to_include"], content
    )

    complete = await client.post(
        f"/files/{init_body['file_id']}/complete", headers=auth_headers(token)
    )
    assert complete.status_code == HTTP_200_OK
    assert complete.json()["state"] == models.FileObjectState.SCANNING.value

    # Run scan synchronously
    scan_file(init_body["file_id"])
    scan_file(init_body["file_id"])  # idempotent second call

    db = SessionLocal()
    refreshed = db.get(models.FileObject, init_body["file_id"])
    assert refreshed.state == models.FileObjectState.ACTIVE
    counter = db.get(models.UsageCounter, refreshed.owner_id)
    assert counter is not None
    assert counter.files_count == 1
    assert counter.bytes_stored == len(content)
    db.close()

    download = await client.post(
        f"/files/{init_body['file_id']}/download-url", headers=auth_headers(token)
    )
    assert download.status_code == HTTP_200_OK
    assert "download_url" in download.json()


@pytest.mark.asyncio
async def test_rate_limit_login(client):
    # register once
    await client.post(
        "/auth/register", json={"email": "rl@example.com", "password": "pass1234"}
    )
    last_status = None
    for _ in range(6):
        resp = await client.post(
            "/auth/login", json={"email": "rl@example.com", "password": "pass1234"}
        )
        last_status = resp.status_code
    assert last_status == HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_rate_limit_files_init(client):
    token = await register_and_get_token(client, email="rlfile@example.com")
    checksum = hashlib.sha256(b"x").hexdigest()
    last_status = None
    for _ in range(11):
        resp = await client.post(
            "/files/init",
            headers=auth_headers(token),
            json={
                "original_filename": "x.txt",
                "content_type": "text/plain",
                "checksum_sha256": checksum,
            },
        )
        last_status = resp.status_code
    assert last_status == HTTP_429_TOO_MANY_REQUESTS


@pytest.mark.asyncio
async def test_quota_blocks_init_when_at_limit(client):
    token = await register_and_get_token(client, email="quota@example.com")
    db = SessionLocal()
    user = db.query(models.User).filter_by(email="quota@example.com").first()
    db.add(models.UsageCounter(user_id=user.id, files_count=200, bytes_stored=0))
    db.commit()
    db.close()

    checksum = hashlib.sha256(b"y").hexdigest()
    resp = await client.post(
        "/files/init",
        headers=auth_headers(token),
        json={
            "original_filename": "y.txt",
            "content_type": "text/plain",
            "checksum_sha256": checksum,
        },
    )
    assert resp.status_code == HTTP_403_FORBIDDEN
