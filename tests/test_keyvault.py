import os
from unittest.mock import MagicMock

os.environ.setdefault("KEY_VAULT_URL", "https://test-vault.vault.azure.net/")

from azure.core.exceptions import ResourceNotFoundError
from fastapi import HTTPException
import pytest

from app import keyvault
from app.models import SecretCreate, SecretUpdate

ID = "pw-" + "1" * 32
MISSING_ID = "pw-" + "0" * 32


class FakeProps:
    def __init__(self, name, tags, enabled=True):
        self.name = name
        self.tags = tags
        self.enabled = enabled


class FakeSecret:
    def __init__(self, name, value, tags, enabled=True):
        self.value = value
        self.properties = FakeProps(name, tags, enabled)


@pytest.fixture(autouse=True)
def fake_client(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(keyvault, "_client", client)
    return client


def test_list_mine_filters_by_owner_and_enabled(fake_client):
    fake_client.list_properties_of_secrets.return_value = [
        FakeProps(ID, {"owner": "alice@example.com", "site": "a.com", "username": "a", "notes": "", "created_at": "1"}),
        FakeProps("pw-2", {"owner": "bob@example.com", "site": "b.com", "username": "b", "notes": "", "created_at": "2"}),
        FakeProps("pw-3", {"owner": "alice@example.com", "site": "c.com", "username": "c", "notes": "", "created_at": "3"}, enabled=False),
    ]
    result = keyvault.list_mine("alice@example.com")
    assert [s.id for s in result] == [ID]


def test_reveal_returns_password_for_owner(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "secretpass", {"owner": "alice@example.com"}
    )
    assert keyvault.reveal(ID, "alice@example.com") == "secretpass"


def test_reveal_forbidden_for_non_owner(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "secretpass", {"owner": "alice@example.com"}
    )
    with pytest.raises(HTTPException) as exc_info:
        keyvault.reveal(ID, "mallory@example.com")
    assert exc_info.value.status_code == 403


def test_reveal_not_found(fake_client):
    fake_client.get_secret.side_effect = ResourceNotFoundError("missing")
    with pytest.raises(HTTPException) as exc_info:
        keyvault.reveal(MISSING_ID, "alice@example.com")
    assert exc_info.value.status_code == 404


def test_update_with_password_sets_new_secret(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "oldpass", {"owner": "alice@example.com", "site": "old.com", "username": "old", "notes": ""}
    )
    keyvault.update(
        ID, "alice@example.com",
        SecretUpdate(site="new.com", username="new", password="newpass", notes="n"),
    )
    fake_client.set_secret.assert_called_once()
    fake_client.update_secret_properties.assert_not_called()


def test_update_without_password_only_updates_tags(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "oldpass", {"owner": "alice@example.com", "site": "old.com", "username": "old", "notes": ""}
    )
    keyvault.update(
        ID, "alice@example.com",
        SecretUpdate(site="new.com", username="new", password="", notes="n"),
    )
    fake_client.update_secret_properties.assert_called_once()
    fake_client.set_secret.assert_not_called()


def test_update_forbidden_for_non_owner(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "oldpass", {"owner": "alice@example.com", "site": "old.com", "username": "old", "notes": ""}
    )
    with pytest.raises(HTTPException) as exc_info:
        keyvault.update(
            ID, "mallory@example.com",
            SecretUpdate(site="new.com", username="new", password="", notes="n"),
        )
    assert exc_info.value.status_code == 403
    fake_client.update_secret_properties.assert_not_called()
    fake_client.set_secret.assert_not_called()


def test_delete_forbidden_for_non_owner(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "oldpass", {"owner": "alice@example.com"}
    )
    with pytest.raises(HTTPException) as exc_info:
        keyvault.delete(ID, "mallory@example.com")
    assert exc_info.value.status_code == 403
    fake_client.begin_delete_secret.assert_not_called()


def test_delete_calls_begin_delete_for_owner(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        ID, "oldpass", {"owner": "alice@example.com"}
    )
    keyvault.delete(ID, "alice@example.com")
    fake_client.begin_delete_secret.assert_called_once_with(ID)


def test_create_sets_owner_tag(fake_client):
    secret_id = keyvault.create(
        "alice@example.com",
        SecretCreate(site="new.com", username="alice", password="pw", notes="n"),
    )
    assert secret_id.startswith("pw-")
    args, kwargs = fake_client.set_secret.call_args
    assert kwargs["tags"]["owner"] == "alice@example.com"
    assert kwargs["tags"]["site"] == "new.com"


@pytest.mark.parametrize("bad_id", ["pw-1", "other-secret", "pw-" + "G" * 32, ID + "x"])
def test_malformed_id_is_404_without_vault_lookup(fake_client, bad_id):
    with pytest.raises(HTTPException) as exc_info:
        keyvault.reveal(bad_id, "alice@example.com")
    assert exc_info.value.status_code == 404
    fake_client.get_secret.assert_not_called()
