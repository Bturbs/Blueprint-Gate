from datetime import datetime

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)
    database_url: str = "sqlite:///./adp.db"
    control_token: str = ""
    worker_token: str = ""
    hybrid_mode: bool = False
    github_token: str = ""
    github_app_id: str = ""
    github_installation_id: str = ""
    github_private_key_path: str = ""
    github_webhook_secret: str = ""
    github_webhook_previous_secret: str = ""
    github_webhook_previous_until: datetime | None = None
    github_api_url: str = "https://api.github.com"
    worker_id: str = "local-worker"
    threat_tool_root: str = ""
    log_dir: str = "./logs"


settings = Settings()
