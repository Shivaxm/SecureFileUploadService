import hashlib

import magic


def compute_checksum(data: bytes, algorithm: str = "sha256") -> str:
    # TODO: stream large files
    if algorithm != "sha256":
        raise ValueError("Unsupported algorithm")
    digest = hashlib.sha256()
    digest.update(data)
    return digest.hexdigest()


def sniff_mime(data: bytes) -> str:
    # TODO: support streaming detection
    return magic.from_buffer(data, mime=True)
