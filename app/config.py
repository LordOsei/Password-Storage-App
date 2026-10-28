from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    key_vault_url: str
    auth_mode: str = "header"  # "header" (prod, Easy Auth) or "dev" (local)
    local_dev_user: str = ""


settings = Settings()
