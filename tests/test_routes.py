import os
from unittest.mock import MagicMock

os.environ.setdefault("KEY_VAULT_URL", "https://test-vault.vault.azure.net/")

from azure.core.exceptions import ResourceNotFoundError
from fastapi.testclient import TestClient
import pytest

from app import keyvault
from app.config import settings
from app.main import app

ID = "pw-" + "1" * 32
MISSING_ID = "pw-" + "0" * 32

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
        ID, "secretpass", {"owner": "alice@example.com", "site": "a.com", "username": "alice", "notes": ""}
    )


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_missing_auth_header_is_401(client):
    assert client.get("/").status_code == 401


def test_index_lists_only_own_entries_without_fetching_values(client, fake_client):
    fake_client.list_properties_of_secrets.return_value = [
        FakeProps(ID, {"owner": "alice@example.com", "site": "alice-site.com", "username": "a", "created_at": "1"}),
        FakeProps("pw-2", {"owner": "bob@example.com", "site": "bob-site.com", "username": "b", "created_at": "2"}),
    ]
    res = client.get("/", headers=ALICE)
    assert res.status_code == 200
    assert "alice-site.com" in res.text
    assert "bob-site.com" not in res.text
    fake_client.get_secret.assert_not_called()


def test_reveal_returns_password_and_is_not_cached(client, alice_secret):
    res = client.get(f"/secrets/{ID}/reveal", headers=ALICE)
    assert res.status_code == 200
    assert res.json() == {"password": "secretpass"}
    assert res.headers["cache-control"] == "no-store"


def test_reveal_forbidden_for_non_owner(client, alice_secret):
    assert client.get(f"/secrets/{ID}/reveal", headers=MALLORY).status_code == 403


def test_reveal_not_found(client, fake_client):
    fake_client.get_secret.side_effect = ResourceNotFoundError("missing")
    assert client.get(f"/secrets/{MISSING_ID}/reveal", headers=ALICE).status_code == 404


def test_edit_form_forbidden_for_non_owner(client, alice_secret):
    assert client.get(f"/secrets/{ID}/edit", headers=MALLORY).status_code == 403


def test_create_redirects_and_tags_owner(client, fake_client):
    res = client.post("/secrets", data=FORM, headers=ALICE)
    assert res.status_code == 303
    assert res.headers["location"] == "/"
    assert fake_client.set_secret.call_args.kwargs["tags"]["owner"] == "alice@example.com"


def test_update_without_password_only_updates_tags(client, fake_client, alice_secret):
    res = client.post(f"/secrets/{ID}/update", data={**FORM, "password": ""}, headers=ALICE)
    assert res.status_code == 303
    fake_client.update_secret_properties.assert_called_once()
    fake_client.set_secret.assert_not_called()


def test_delete_forbidden_for_non_owner(client, fake_client, alice_secret):
    assert client.post(f"/secrets/{ID}/delete", headers=MALLORY).status_code == 403
    fake_client.begin_delete_secret.assert_not_called()


def test_delete_redirects_for_owner(client, fake_client, alice_secret):
    res = client.post(f"/secrets/{ID}/delete", headers=ALICE)
    assert res.status_code == 303
    fake_client.begin_delete_secret.assert_called_once_with(ID)


@pytest.mark.parametrize("extra", [
    {"Sec-Fetch-Site": "cross-site"},
    {"Sec-Fetch-Site": "same-site"},
    {"Origin": "https://evil.example.com"},
])
def test_cross_site_post_is_blocked(client, fake_client, alice_secret, extra):
    res = client.post(f"/secrets/{ID}/delete", headers={**ALICE, **extra})
    assert res.status_code == 403
    fake_client.begin_delete_secret.assert_not_called()


@pytest.mark.parametrize("extra", [
    {"Sec-Fetch-Site": "same-origin"},
    {"Origin": "http://testserver"},
])
def test_same_origin_post_is_allowed(client, fake_client, alice_secret, extra):
    res = client.post(f"/secrets/{ID}/delete", headers={**ALICE, **extra})
    assert res.status_code == 303
    fake_client.begin_delete_secret.assert_called_once()


def test_null_origin_post_is_blocked(client, fake_client, alice_secret):
    res = client.post(f"/secrets/{ID}/delete", headers={**ALICE, "Origin": "null"})
    assert res.status_code == 403
    fake_client.begin_delete_secret.assert_not_called()


def test_post_allowed_when_proxy_rewrites_host_but_forwards_original(client, fake_client, alice_secret):
    headers = {
        **ALICE,
        "Host": "127.0.0.1:8000",
        "X-Forwarded-Host": "pwstore.example.net",
        "Origin": "https://pwstore.example.net",
    }
    res = client.post(f"/secrets/{ID}/delete", headers=headers)
    assert res.status_code == 303
    fake_client.begin_delete_secret.assert_called_once()


def test_post_allowed_when_origin_matches_app_service_hostname(client, fake_client, alice_secret, monkeypatch):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "pwstore.example.net")
    headers = {**ALICE, "Host": "127.0.0.1:8000", "Origin": "https://pwstore.example.net"}
    res = client.post(f"/secrets/{ID}/delete", headers=headers)
    assert res.status_code == 303


def test_referrer_policy_keeps_origin_on_own_posts(client, fake_client):
    fake_client.list_properties_of_secrets.return_value = []
    res = client.get("/", headers=ALICE)
    assert res.headers["referrer-policy"] == "same-origin"


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


def test_reveal_malformed_id_is_404(client, fake_client):
    assert client.get("/secrets/not-a-pw-id/reveal", headers=ALICE).status_code == 404
    fake_client.get_secret.assert_not_called()


def test_create_invalid_input_rerenders_form(client, fake_client):
    res = client.post("/secrets", data={**FORM, "site": "x" * 201, "password": "typed-secret"}, headers=ALICE)
    assert res.status_code == 422
    assert "Site: String should have at most 200 characters" in res.text
    assert 'value="alice"' in res.text  # username kept
    assert "typed-secret" not in res.text  # password never echoed
    fake_client.set_secret.assert_not_called()


def test_update_invalid_input_rerenders_form(client, fake_client, alice_secret):
    res = client.post(f"/secrets/{ID}/update", data={**FORM, "notes": "n" * 257}, headers=ALICE)
    assert res.status_code == 422
    assert "Notes: String should have at most 256 characters" in res.text
    fake_client.update_secret_properties.assert_not_called()
    fake_client.set_secret.assert_not_called()


def test_update_invalid_input_still_checks_ownership(client, fake_client, alice_secret):
    res = client.post(f"/secrets/{ID}/update", data={**FORM, "notes": "n" * 257}, headers=MALLORY)
    assert res.status_code == 403
    assert "n" * 257 not in res.text


def test_header_has_sign_out_link(client, fake_client):
    fake_client.list_properties_of_secrets.return_value = []
    res = client.get("/", headers=ALICE)
    assert res.status_code == 200
    assert 'href="/.auth/logout"' in res.text


def test_sign_out_link_hidden_in_dev_mode(client, fake_client, monkeypatch):
    monkeypatch.setattr(settings, "auth_mode", "dev")
    monkeypatch.setattr(settings, "local_dev_user", "alice@example.com")
    fake_client.list_properties_of_secrets.return_value = []
    res = client.get("/")
    assert res.status_code == 200
    assert "/.auth/logout" not in res.text


def test_welcome_is_public_and_has_link_preview_tags(client, fake_client, monkeypatch):
    monkeypatch.setenv("WEBSITE_HOSTNAME", "pw-app.azurewebsites.net")
    r = client.get("/welcome")
    assert r.status_code == 200
    assert 'property="og:title" content="Password Store"' in r.text
    assert 'content="https://pw-app.azurewebsites.net/static/og-image.png"' in r.text
    assert 'href="/.auth/login/aad?post_login_redirect_uri=/"' in r.text
    assert r.headers["Content-Security-Policy"]
    # The public page must never touch the vault.
    assert not fake_client.method_calls


def test_welcome_ignores_identity_header(client, fake_client):
    r = client.get("/welcome", headers=ALICE)
    assert "alice@example.com" not in r.text
    assert "Sign out" not in r.text


def test_preview_assets_are_served(client):
    assert client.get("/static/og-image.png").headers["content-type"] == "image/png"
    assert client.get("/static/favicon.svg").headers["content-type"] == "image/svg+xml"


def test_pages_have_favicon_and_titles(client, fake_client):
    fake_client.list_properties_of_secrets.return_value = []
    r = client.get("/", headers=ALICE)
    assert '<link rel="icon" href="/static/favicon.svg"' in r.text
    assert "<title>My Passwords · Password Store</title>" in r.text


def test_welcome_does_not_reflect_host_header(client, monkeypatch):
    monkeypatch.delenv("WEBSITE_HOSTNAME", raising=False)
    r = client.get("/welcome", headers={"Host": "evil.example"})
    assert r.status_code == 200
    assert "evil.example" not in r.text
