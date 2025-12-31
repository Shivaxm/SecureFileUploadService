import pytest


@pytest.mark.asyncio
async def test_upload_and_download_flow(client):
    # TODO: register user, login, request presigned upload, simulate callback, request download
    response = await client.get("/health/live")
    assert response.status_code == 200
    # TODO: flesh out end-to-end scenario

