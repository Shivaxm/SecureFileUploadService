from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_SIZE_BYTES = 50 * 1024 * 1024


@dataclass(frozen=True)
class FileTypePolicy:
    allowed: bool
    expected_mimes: tuple[str, ...]
    sniff_mimes: tuple[str, ...]
    magic_prefixes: tuple[bytes, ...] = ()
    max_size_bytes: int | None = None


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    reason: str | None = None
    details: dict[str, str | int] | None = None


OFFICE_SNIFF_MIMES = (
    "application/zip",
    "application/octet-stream",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
)
OFFICE_DECLARED_MIMES = (
    "application/zip",
    "application/octet-stream",
)

FILE_TYPE_POLICIES: dict[str, FileTypePolicy] = {
    ".pdf": FileTypePolicy(
        allowed=True,
        expected_mimes=("application/pdf",),
        sniff_mimes=("application/pdf",),
        magic_prefixes=(b"%PDF-",),
    ),
    ".txt": FileTypePolicy(
        allowed=True,
        expected_mimes=("text/plain",),
        sniff_mimes=("text/plain",),
    ),
    ".csv": FileTypePolicy(
        allowed=True,
        expected_mimes=("text/csv", "application/csv"),
        sniff_mimes=("text/plain", "text/csv"),
    ),
    ".png": FileTypePolicy(
        allowed=True,
        expected_mimes=("image/png",),
        sniff_mimes=("image/png",),
        magic_prefixes=(b"\x89PNG\r\n\x1a\n",),
    ),
    ".jpg": FileTypePolicy(
        allowed=True,
        expected_mimes=("image/jpeg",),
        sniff_mimes=("image/jpeg",),
        magic_prefixes=(b"\xff\xd8\xff",),
    ),
    ".jpeg": FileTypePolicy(
        allowed=True,
        expected_mimes=("image/jpeg",),
        sniff_mimes=("image/jpeg",),
        magic_prefixes=(b"\xff\xd8\xff",),
    ),
    ".gif": FileTypePolicy(
        allowed=True,
        expected_mimes=("image/gif",),
        sniff_mimes=("image/gif",),
        magic_prefixes=(b"GIF87a", b"GIF89a"),
    ),
    # Office OpenXML files are ZIP containers; accept zip-like sniff values,
    # but require extension + declared MIME + ZIP magic ("PK").
    ".docx": FileTypePolicy(
        allowed=True,
        expected_mimes=(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            *OFFICE_DECLARED_MIMES,
        ),
        sniff_mimes=OFFICE_SNIFF_MIMES,
        magic_prefixes=(b"PK\x03\x04",),
    ),
    ".xlsx": FileTypePolicy(
        allowed=True,
        expected_mimes=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            *OFFICE_DECLARED_MIMES,
        ),
        sniff_mimes=OFFICE_SNIFF_MIMES,
        magic_prefixes=(b"PK\x03\x04",),
    ),
    ".pptx": FileTypePolicy(
        allowed=True,
        expected_mimes=(
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            *OFFICE_DECLARED_MIMES,
        ),
        sniff_mimes=OFFICE_SNIFF_MIMES,
        magic_prefixes=(b"PK\x03\x04",),
    ),
}

ALLOWED_CONTENT_TYPES = {
    mime
    for policy in FILE_TYPE_POLICIES.values()
    if policy.allowed
    for mime in policy.expected_mimes
}


def _base_mime(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(";", 1)[0].strip().lower()


def _policy_for_filename(filename: str) -> tuple[str, FileTypePolicy] | None:
    ext = Path(filename).suffix.lower()
    policy = FILE_TYPE_POLICIES.get(ext)
    if not policy:
        return None
    return ext, policy


def validate_upload_metadata(  # noqa: PLR0913
    *,
    original_filename: str,
    declared_content_type: str,
    sniffed_content_type: str | None,
    size_bytes: int | None,
    sample_bytes: bytes | None,
    max_size_bytes: int | None = DEFAULT_MAX_SIZE_BYTES,
) -> ValidationResult:
    reason: str | None = None
    details: dict[str, str | int] | None = None

    resolved = _policy_for_filename(original_filename)
    if not resolved:
        reason = "disallowed_extension"
        details = {"filename": original_filename}
    else:
        ext, policy = resolved
        declared_base = _base_mime(declared_content_type)
        sniffed_base = _base_mime(sniffed_content_type)

        if not policy.allowed:
            reason = "disallowed_extension"
            details = {"ext": ext}
        elif (
            max_size_bytes is not None
            and size_bytes is not None
            and size_bytes > max_size_bytes
        ):
            reason = "too_large"
            details = {"size": size_bytes, "max": max_size_bytes}
        elif (
            policy.max_size_bytes
            and size_bytes is not None
            and size_bytes > policy.max_size_bytes
        ):
            reason = "type_size_limit"
            details = {"size": size_bytes, "max": policy.max_size_bytes, "ext": ext}
        elif declared_base not in policy.expected_mimes:
            reason = "declared_mime_mismatch"
            details = {"declared": declared_base or "none", "ext": ext}
        elif sniffed_base is None:
            reason = "sniff_missing"
            details = {"ext": ext}
        elif sniffed_base not in policy.sniff_mimes:
            reason = "sniff_mismatch"
            details = {
                "sniffed": sniffed_base,
                "declared": declared_base or "none",
                "ext": ext,
            }
        elif policy.magic_prefixes and not sample_bytes:
            reason = "magic_missing"
            details = {"ext": ext}
        elif policy.magic_prefixes and not any(
            sample_bytes.startswith(prefix) for prefix in policy.magic_prefixes
        ):
            reason = "magic_mismatch"
            details = {"ext": ext, "sniffed": sniffed_base or "none"}

    if reason:
        return ValidationResult(ok=False, reason=reason, details=details)
    return ValidationResult(ok=True)
