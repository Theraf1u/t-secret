from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    bot_token: SecretStr
    bot_username: str = "TSecretBot"
    database_url: str
    redis_url: str
    master_key: SecretStr
    telegram_proxy: str | None = None
    secret_message_ttl: int = Field(default=60, ge=10, le=3600)
    cleanup_interval: int = Field(default=60, ge=10, le=3600)
    default_secret_ttl: int = Field(default=86400, ge=300)
    log_level: str = "INFO"
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost: int = Field(default=65536, ge=8192, le=1048576)
    argon2_parallelism: int = Field(default=2, ge=1, le=16)
    pin_max_attempts: int = Field(default=5, ge=1, le=20)
    pin_lockout_seconds: int = Field(default=900, ge=60, le=86400)
    open_rate_limit: int = Field(default=60, ge=1, le=1000)
    open_rate_window: int = Field(default=3600, ge=10, le=86400)
    token_rate_limit: int = Field(default=60, ge=1, le=5000)
    token_rate_window: int = Field(default=60, ge=10, le=3600)
    max_secret_file_size_mb: int = Field(default=20, ge=1, le=100)
    secret_storage_path: str = "/data/secrets"
    request_ttl: int = Field(default=86400, ge=300, le=2592000)
    generator_message_ttl: int = Field(default=45, ge=10, le=300)
    admin_ids: str = ""
    start_rate_limit: int = Field(default=30, ge=1, le=1000)
    start_rate_window: int = Field(default=60, ge=10, le=86400)
    create_rate_limit: int = Field(default=20, ge=1, le=1000)
    create_rate_window: int = Field(default=3600, ge=10, le=86400)
    request_rate_limit: int = Field(default=20, ge=1, le=1000)
    request_rate_window: int = Field(default=3600, ge=10, le=86400)
    file_rate_limit: int = Field(default=20, ge=1, le=1000)
    file_rate_window: int = Field(default=3600, ge=10, le=86400)
    worker_heartbeat_ttl: int = Field(default=180, ge=30, le=3600)

    @property
    def admin_id_set(self) -> set[int]:
        return {int(value.strip()) for value in self.admin_ids.split(",") if value.strip().isdigit()}

    @field_validator("bot_username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.removeprefix("@").strip()


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
