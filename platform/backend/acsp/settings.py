from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_path: str = "/data/acsp.db"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    processor_host: str = "0.0.0.0"
    processor_port: int = 8787
    internal_secret: str = "change-me-in-production"
    api_gateway_url: str = "http://acsp-api:8000"
    cors_origins: str = "*"


@lru_cache
def get_settings() -> Settings:
    return Settings()
