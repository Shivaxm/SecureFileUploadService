from functools import lru_cache

from pydantic import Field
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

    minio_endpoint: str
    minio_public_endpoint: str | None = "http://localhost:9000"
    minio_access_key: str
    minio_secret_key: str
    minio_bucket: str

    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expires_seconds: int = 3600

    rate_limit_default: int = 100
    quota_default_bytes: int = 1_073_741_824


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
