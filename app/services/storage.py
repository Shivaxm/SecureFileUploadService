from dataclasses import dataclass
import boto3
from botocore.exceptions import ClientError
from app.core.config import settings


@dataclass
class PresignedUpload:
    url: str
    headers: dict[str, str]


class StorageClient:
    def __init__(self):
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.minio_endpoint,
            aws_access_key_id=settings.minio_access_key,
            aws_secret_access_key=settings.minio_secret_key,
        )
        self.bucket = settings.minio_bucket
        self._ensure_bucket()

    @property
    def not_found_exc(self):
        return ClientError

    def _ensure_bucket(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError:
            try:
                self.client.create_bucket(Bucket=self.bucket)
            except ClientError:
                # Bucket creation may fail if already created by a race; ignore
                pass

    def generate_presigned_put(
        self,
        key: str,
        content_type: str,
        expires_in: int = 3600,
        extra_metadata: dict[str, str] | None = None,
    ) -> PresignedUpload:
        metadata = extra_metadata or {}
        url = self.client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ContentType": content_type,
                "Metadata": metadata,
            },
            ExpiresIn=expires_in,
        )
        headers = {"Content-Type": content_type}
        for k, v in metadata.items():
            headers[f"x-amz-meta-{k}"] = v
        return PresignedUpload(url=url, headers=headers)

    def generate_presigned_get(self, key: str, expires: int = 3600) -> str:
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires,
        )

    def head_object(self, bucket: str, key: str):
        return self.client.head_object(Bucket=bucket, Key=key)

    def iter_object(self, bucket: str, key: str, chunk_size: int = 1024 * 1024):
        obj = self.client.get_object(Bucket=bucket, Key=key)
        body = obj["Body"]
        while True:
            chunk = body.read(chunk_size)
            if not chunk:
                break
            yield chunk

    def get_object_range(self, bucket: str, key: str, byte_range: str) -> bytes | None:
        try:
            obj = self.client.get_object(Bucket=bucket, Key=key, Range=byte_range)
            return obj["Body"].read()
        except ClientError:
            return None

