import os
from unittest.mock import MagicMock

os.environ.setdefault("KEY_VAULT_URL", "https://test-vault.vault.azure.net/")

from azure.core.exceptions import ResourceNotFoundError
from fastapi.testclient import TestClient
import pytest

from app import keyvault
from app.config import settings
from app.main import app

ALICE = {"X-MS-CLIENT-PRINCIPAL-NAME": "alice@example.com"}
MALLORY = {"X-MS-CLIENT-PRINCIPAL-NAME": "mallory@example.com"}
FORM = {"site": "a.com", "username": "alice", "password": "pw", "notes": ""}


class FakeProps:
    def __init__(self, name, tags, enabled=True):
        self.name = name
        self.tags = tags
        self.enabled = enabled


class FakeSecret:
    def __init__(self, name, value, tags):
        self.value = value
        self.properties = FakeProps(name, tags)


@pytest.fixture(autouse=True)
def fake_client(monkeypatch):
    client = MagicMock()
    monkeypatch.setattr(keyvault, "_client", client)
    monkeypatch.setattr(settings, "auth_mode", "header")
    return client


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


@pytest.fixture
def alice_secret(fake_client):
    fake_client.get_secret.return_value = FakeSecret(
        "pw-1", "secretpass", {"owner": "alice@example.com", "site": "a.com", "username": "alice", "notes": ""}
    )


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_missing_auth_header_is_401(client):
    assert client.get("/").status_code == 401


def test_index_lists_only_own_entries_without_fetching_values(client, fake_client):
    fake_client.list_properties_of_secrets.return_value = [
        FakeProps("pw-1", {"owner": "alice@example.com", "site": "alice-site.com", "username": "a", "created_at": "1"}),
        FakeProps("pw-2", {"owner": "bob@example.com", "site": "bob-site.com", "username": "b", "created_at": "2"}),
    ]
    res = client.get("/", headers=ALICE)
    assert res.status_code == 200
    assert "alice-site.com" in res.text
    assert "bob-site.com" not in res.text
    fake_client.get_secret.assert_not_called()


def test_reveal_returns_password_and_is_not_cached(client, alice_secret):
    res = client.get("/secrets/pw-1/reveal", headers=ALICE)
    assert res.status_code == 200
    assert res.json() == {"password": "secretpass"}
    assert res.headers["cache-control"] == "no-store"


def test_reveal_forbidden_for_non_owner(client, alice_secret):
    assert client.get("/secrets/pw-1/reveal", headers=MALLORY).status_code == 403


def test_reveal_not_found(client, fake_client):
    fake_client.get_secret.side_effect = ResourceNotFoundError("missing")
    assert client.get("/secrets/pw-missing/reveal", headers=ALICE).status_code == 404


def test_edit_form_forbidden_for_non_owner(client, alice_secret):
    assert client.get("/secrets/pw-1/edit", headers=MALLORY).status_code == 403


def test_create_redirects_and_tags_owner(client, fake_client):
    res = client.post("/secrets", data=FORM, headers=ALICE)
    assert res.status_code == 303
    assert res.headers["location"] == "/"
    assert fake_client.set_secret.call_args.kwargs["tags"]["owner"] == "alice@example.com"


def test_update_without_password_only_updates_tags(client, fake_client, alice_secret):
    res = client.post("/secrets/pw-1/update", data={**FORM, "password": ""}, headers=ALICE)
    assert res.status_code == 303
    fake_client.update_secret_properties.assert_called_once()
    fake_client.set_secret.assert_not_called()


def test_delete_forbidden_for_non_owner(client, fake_client, alice_secret):
    assert client.post("/secrets/pw-1/delete", headers=MALLORY).status_code == 403
    fake_client.begin_delete_secret.assert_not_called()


def test_delete_redirects_for_owner(client, fake_client, alice_secret):
    res = client.post("/secrets/pw-1/delete", headers=ALICE)
    assert res.status_code == 303
    fake_client.begin_delete_secret.assert_called_once_with("pw-1")


@pytest.mark.parametrize("extra", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example.com"},
])
def test_cross_site_post_is_blocked(client, fake_client, alice_secret, extra):
    res = client.post("/secrets/pw-1/delete", headers={**ALICE, **extra})
    assert res.status_code == 403
    fake_client.begin_delete_secret.assert_not_called()


@pytest.mark.parametrize("extra", [
    {"Sec-Fetch-Site": "same-origin"},
    {"Origin": "http://testserver"},
])
def test_same_origin_post_is_allowed(client, fake_client, alice_secret, extra):
    res = client.post("/secrets/pw-1/delete", headers={**ALICE, **extra})
    assert res.status_code == 303
    fake_client.begin_delete_secret.assert_called_once()


def test_security_headers_present(client, fake_client):
    fake_client.list_properties_of_secrets.return_value = []
    res = client.get("/", headers=ALICE)
    assert "frame-ancestors 'none'" in res.headers["content-security-policy"]
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"


def test_static_files_are_cacheable(client):
    res = client.get("/static/app.js")
    assert res.status_code == 200
    assert res.headers.get("cache-control") != "no-store"
