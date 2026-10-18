from datetime import datetime

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)
    database_url: str = "sqlite:///./adp.db"
    control_token: str = ""
    human_identity_required: bool = False
    human_reviewer_ids: str = ""
    human_operator_ids: str = ""
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

    @model_validator(mode="after")
    def reject_hybrid_personal_token(self):
        if self.hybrid_mode and self.github_token:
            raise ValueError("Hybrid control must not have GITHUB_TOKEN in its environment")
        return self


settings = Settings()
