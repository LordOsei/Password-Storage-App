# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A small FastAPI password manager for a trusted group. There is **no database**: every entry is an Azure Key Vault secret. It is deployed to Azure App Service (Linux, Python 3.12), and Easy Auth (Microsoft Entra) handles sign-in.

## Commands

```bash
source .venv/bin/activate
pip install -r requirements.txt

uvicorn app.main:app --reload --port 8000              # run locally (needs .env and `az login`)
pytest                                                 # all tests
pytest tests/test_keyvault.py::test_reveal_not_found   # single test

az webapp up --resource-group $RG --name $APP_NAME --runtime "PYTHON:3.12"   # deploy
```

There is no linter or formatter configured. Production startup is `gunicorn -w 2 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000 app.main:app`.

## Configuration

`app/config.py` loads settings with pydantic-settings, reading from env vars or `.env` (see `.env.example`):
- `KEY_VAULT_URL` (required). Local dev should point at a separate **dev** vault, never the real one.
- `AUTH_MODE`: `header` (prod, the default) or `dev`.
- `LOCAL_DEV_USER`: the identity to act as when `AUTH_MODE=dev`.

`settings` and the Key Vault `_client` are both created at **import time**. Importing `app.keyvault` without `KEY_VAULT_URL` set will fail, which is why the tests set it with `os.environ.setdefault` before they import from `app`.

## Architecture

**Data model in Key Vault (`app/keyvault.py`)**: each entry is a secret named `pw-<uuid hex>`.
- The secret **value** is the password.
- **Tags** hold `owner`, `site`, `username`, `notes`, and `created_at`.
- The list view reads only tags (`list_properties_of_secrets`), so it never fetches a password value. Keep it that way.
- Field limits in `app/models.py` (such as `notes` ≤ 256) exist because Key Vault caps the length of tag values.

**Ownership enforcement**: every per-entry operation (reveal, get_summary, update, delete) goes through `_fetch_owned`. It returns 404 when the secret is missing and 403 when the `owner` tag doesn't match the current user. Any new per-entry operation must also call `_fetch_owned`. The UI is not trusted for this check.

**Updates and versions**: `update` calls `set_secret` (which creates a new secret version) only when a new password is supplied. Otherwise it calls `update_secret_properties`, which changes tags without creating a version. Tests rely on this distinction.

**Delete** is a soft delete (`begin_delete_secret`), so deleted entries can still be recovered from the vault's "Deleted secrets".

**Auth (`app/auth.py`)**: the `get_current_user` dependency reads the `X-MS-CLIENT-PRINCIPAL-NAME` header that Easy Auth injects. In `dev` mode it returns `LOCAL_DEV_USER` instead, so the ownership logic runs the same way locally. Every route depends on it.

**Credentials**: `DefaultAzureCredential` uses the App Service managed identity in production and your `az login` session locally. Both need the `Key Vault Secrets Officer` role on the vault.

**Web layer**:
- The UI is server-rendered with Jinja2 (`app/templates/`, `app/templating.py`).
- `app/routes/pages.py` serves the HTML pages.
- `app/routes/secrets.py` handles form POSTs, which use the redirect-after-POST pattern (303 redirect to `/`).
- `GET /secrets/{id}/reveal` is the only JSON endpoint. `app/static/app.js` calls it to reveal a password and copy it to the clipboard.
- `/healthz` is the health check.

## Testing

`tests/test_keyvault.py` monkeypatches `keyvault._client` with a `MagicMock` in an autouse fixture, so tests never reach Azure. The `FakeProps` and `FakeSecret` helpers stand in for SDK objects. Routes and templates have no tests.
