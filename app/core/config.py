from functools import lru_cache

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "secure-file-upload-service"
    app_env: str = Field(default="dev", alias="ENV")
    debug: bool = Field(default=False, alias="APP_DEBUG")
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    database_url: str
    redis_url: str

    # Storage settings support both legacy MINIO_* and deploy-time S3_* names.
    minio_endpoint: str | None = Field(
        default=None,
        validation_alias=AliasChoices("S3_ENDPOINT", "MINIO_ENDPOINT"),
    )
    minio_public_endpoint: str | None = Field(
        default=None,
        validation_alias=AliasChoices("S3_PUBLIC_ENDPOINT", "MINIO_PUBLIC_ENDPOINT"),
    )
    minio_access_key: str = Field(
        validation_alias=AliasChoices("S3_ACCESS_KEY_ID", "MINIO_ACCESS_KEY")
    )
    minio_secret_key: str = Field(
        validation_alias=AliasChoices("S3_SECRET_ACCESS_KEY", "MINIO_SECRET_KEY")
    )
    minio_bucket: str = Field(
        validation_alias=AliasChoices("S3_BUCKET", "MINIO_BUCKET")
    )
    s3_region: str | None = Field(
        default=None, validation_alias=AliasChoices("S3_REGION", "MINIO_REGION")
    )
    storage_auto_create_bucket: bool = True

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expires_seconds: int = 3600

    upload_presign_ttl_seconds: int = 15 * 60
    download_presign_ttl_seconds: int = 5 * 60

    rate_limit_default: int = 100
    quota_default_bytes: int = 1_073_741_824


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
