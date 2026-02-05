from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import quote

import boto3
from botocore.exceptions import ClientError

from app.core.config import settings

_ASCII_PRINTABLE_START = 32
_ASCII_PRINTABLE_END = 127


@dataclass
class PresignedUpload:
    url: str
    headers: dict[str, str]


class StorageClient:
    def __init__(self):
        self.bucket = settings.minio_bucket
        internal_endpoint = settings.minio_endpoint
        public_endpoint = settings.minio_public_endpoint or internal_endpoint
        common = {
            "aws_access_key_id": settings.minio_access_key,
            "aws_secret_access_key": settings.minio_secret_key,
        }
        if settings.s3_region:
            common["region_name"] = settings.s3_region

        internal_kwargs = common.copy()
        if internal_endpoint:
            internal_kwargs["endpoint_url"] = internal_endpoint
        self.client_internal = boto3.client("s3", **internal_kwargs)

        public_kwargs = common.copy()
        if public_endpoint:
            public_kwargs["endpoint_url"] = public_endpoint
        self.client_public = boto3.client("s3", **public_kwargs)

        if settings.storage_auto_create_bucket:
            self._ensure_bucket()

    @property
    def not_found_exc(self):
        return ClientError

    def _ensure_bucket(self) -> None:
        try:
            self.client_internal.head_bucket(Bucket=self.bucket)
        except ClientError:
            # Bucket creation may fail if already created by a race; ignore
            with suppress(ClientError):
                self.client_internal.create_bucket(Bucket=self.bucket)

    def generate_presigned_put(
        self,
        key: str,
        content_type: str,
        expires_in: int = 3600,
    ) -> PresignedUpload:
        url = self.client_public.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ContentType": content_type,
            },
            ExpiresIn=expires_in,
        )
        headers = {"Content-Type": content_type}
        return PresignedUpload(url=url, headers=headers)

    def generate_presigned_get(self, key: str, expires: int = 3600) -> str:
        return self.client_public.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires,
        )

    def generate_presigned_get_download(
        self,
        *,
        key: str,
        download_filename: str,
        response_content_type: str | None = None,
        expires: int = 3600,
    ) -> str:
        # Prevent header injection and path tricks; S3 will return this via
        # `response-content-disposition` query param, not from our API response.
        safe = (download_filename or "download").replace("\r", "").replace("\n", "")
        safe = safe.split("/")[-1].split("\\")[-1]
        safe_ascii = "".join(
            (
                ch
                if _ASCII_PRINTABLE_START <= ord(ch) < _ASCII_PRINTABLE_END
                and ch not in {'"', "\\"}
                else "_"
            )
            for ch in safe
        )
        encoded = quote(safe, safe="")
        disposition = (
            f"attachment; filename=\"{safe_ascii}\"; filename*=UTF-8''{encoded}"
        )

        params: dict[str, str] = {
            "Bucket": self.bucket,
            "Key": key,
            "ResponseContentDisposition": disposition,
        }
        if response_content_type:
            params["ResponseContentType"] = response_content_type.split(";", 1)[0]

        return self.client_public.generate_presigned_url(
            "get_object",
            Params=params,
            ExpiresIn=expires,
        )

    def head_object(self, bucket: str, key: str):
        return self.client_internal.head_object(Bucket=bucket, Key=key)

    def iter_object(self, bucket: str, key: str, chunk_size: int = 1024 * 1024):
        obj = self.client_internal.get_object(Bucket=bucket, Key=key)
        body = obj["Body"]
        while True:
            chunk = body.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def get_object_range(self, bucket: str, key: str, byte_range: str) -> bytes | None:
        try:
            obj = self.client_internal.get_object(
                Bucket=bucket, Key=key, Range=byte_range
            )
            return obj["Body"].read()
        except ClientError:
            return None
