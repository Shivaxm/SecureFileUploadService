import pytest
from app.services.file_type_policy import validate_upload_metadata


@pytest.mark.parametrize(
    ("filename", "declared", "sniffed", "sample"),
    [
        ("file.pdf", "application/pdf", "application/pdf", b"%PDF-1.7\n"),
        (
            "file.png",
            "image/png",
            "image/png",
            b"\x89PNG\r\n\x1a\nrest",
        ),
        ("file.jpg", "image/jpeg", "image/jpeg", b"\xff\xd8\xff\xee"),
        (
            "file.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
            b"PK\x03\x04payload",
        ),
        (
            "file.docx",
            "application/octet-stream",
            "application/zip",
            b"PK\x03\x04payload",
        ),
    ],
)
def test_validate_upload_metadata_allows_supported_types(
    filename: str, declared: str, sniffed: str, sample: bytes
):
    result = validate_upload_metadata(
        original_filename=filename,
        declared_content_type=declared,
        sniffed_content_type=sniffed,
        size_bytes=1024,
        sample_bytes=sample,
    )

    assert result.ok is True
    assert result.reason is None


def test_validate_upload_metadata_rejects_disallowed_extension():
    result = validate_upload_metadata(
        original_filename="malware.exe",
        declared_content_type="application/octet-stream",
        sniffed_content_type="application/x-dosexec",
        size_bytes=128,
        sample_bytes=b"MZ....",
    )

    assert result.ok is False
    assert result.reason == "disallowed_extension"


def test_validate_upload_metadata_rejects_declared_mime_mismatch():
    result = validate_upload_metadata(
        original_filename="image.png",
        declared_content_type="application/pdf",
        sniffed_content_type="application/pdf",
        size_bytes=128,
        sample_bytes=b"%PDF-1.7",
    )

    assert result.ok is False
    assert result.reason == "declared_mime_mismatch"


def test_validate_upload_metadata_rejects_oversized_file():
    result = validate_upload_metadata(
        original_filename="note.txt",
        declared_content_type="text/plain",
        sniffed_content_type="text/plain",
        size_bytes=11,
        sample_bytes=b"hello world",
        max_size_bytes=10,
    )

    assert result.ok is False
    assert result.reason == "too_large"


def test_validate_upload_metadata_rejects_docx_without_zip_magic():
    result = validate_upload_metadata(
        original_filename="resume.docx",
        declared_content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        sniffed_content_type="application/zip",
        size_bytes=1024,
        sample_bytes=b"not-a-zip",
    )

    assert result.ok is False
    assert result.reason == "magic_mismatch"
