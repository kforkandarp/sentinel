import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    host: str = os.getenv("SENTINEL_HOST", "0.0.0.0")
    port: int = int(os.getenv("SENTINEL_PORT", "8000"))
    environment: str = os.getenv("SENTINEL_ENVIRONMENT", "development")


def get_settings() -> Settings:
    return Settings()