import os
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    key_vault_url: str
    auth_mode: Literal["header", "dev"] = "header"  # "header" (prod, Easy Auth) or "dev" (local)
    local_dev_user: str = ""
    # Comma-separated Entra object IDs allowed to use the app in header mode. Empty denies everyone.
    allowed_object_ids: str = ""

    @property
    def allowed_ids(self) -> frozenset[str]:
        return frozenset(i.strip().lower() for i in self.allowed_object_ids.split(",") if i.strip())

    @model_validator(mode="after")
    def _check_dev_mode(self):
        if self.auth_mode == "header" and os.environ.get("WEBSITE_SITE_NAME") and not self.allowed_ids:
            # Fail loudly at startup rather than silently locking everyone out.
            raise ValueError("ALLOWED_OBJECT_IDS must be set on App Service")
        if self.auth_mode == "dev":
            # App Service always sets WEBSITE_SITE_NAME; dev mode bypasses sign-in, so never allow it there.
            if os.environ.get("WEBSITE_SITE_NAME"):
                raise ValueError("AUTH_MODE=dev is not allowed on App Service")
            if not self.local_dev_user:
                raise ValueError("LOCAL_DEV_USER is required when AUTH_MODE=dev")
        return self


settings = Settings()
