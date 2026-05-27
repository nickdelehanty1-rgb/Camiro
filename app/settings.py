from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # API Keys
    api_key: str = ""  # ANTHROPIC_API_KEY renamed to avoid Railway interception
    embedding_api_key: Optional[str] = None

    # Database
    database_url: str = "postgresql://camiro:camiro@localhost:5432/camiro"

    # App
    app_name: str = "Camiro"
    debug: bool = False
    max_input_chars: int = 50000
    demo_password: Optional[str] = None

    # Security
    redact_secrets: bool = True
    log_submitted_code: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
