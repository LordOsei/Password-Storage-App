import os

os.environ.setdefault("KEY_VAULT_URL", "https://test-vault.vault.azure.net/")

from pydantic import ValidationError
import pytest

from app.config import Settings

VAULT = "https://test-vault.vault.azure.net/"


@pytest.fixture(autouse=True)
def not_on_app_service(monkeypatch):
    monkeypatch.delenv("WEBSITE_SITE_NAME", raising=False)
    # A dev shell (e.g. VS Code loading .env) may export these; the tests must not depend on it.
    monkeypatch.delenv("AUTH_MODE", raising=False)
    monkeypatch.delenv("LOCAL_DEV_USER", raising=False)
    monkeypatch.delenv("ALLOWED_OBJECT_IDS", raising=False)


def test_default_is_header_mode():
    assert Settings(_env_file=None, key_vault_url=VAULT).auth_mode == "header"


def test_unknown_auth_mode_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, key_vault_url=VAULT, auth_mode="off")


def test_dev_mode_requires_local_user():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, key_vault_url=VAULT, auth_mode="dev")


def test_dev_mode_allowed_locally():
    s = Settings(_env_file=None, key_vault_url=VAULT, auth_mode="dev", local_dev_user="me@example.com")
    assert s.local_dev_user == "me@example.com"


def test_dev_mode_refused_on_app_service(monkeypatch):
    monkeypatch.setenv("WEBSITE_SITE_NAME", "pwstore-app")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, key_vault_url=VAULT, auth_mode="dev", local_dev_user="me@example.com")


def test_header_mode_on_app_service_requires_allowlist(monkeypatch):
    monkeypatch.setenv("WEBSITE_SITE_NAME", "pwstore-app")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, key_vault_url=VAULT)


def test_allowlist_is_parsed_and_normalised(monkeypatch):
    monkeypatch.setenv("WEBSITE_SITE_NAME", "pwstore-app")
    s = Settings(_env_file=None, key_vault_url=VAULT, allowed_object_ids=" AAA-1 , bbb-2,, ")
    assert s.allowed_ids == {"aaa-1", "bbb-2"}
