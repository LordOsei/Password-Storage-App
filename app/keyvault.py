import uuid
from datetime import datetime, timezone

from azure.core.exceptions import ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from fastapi import HTTPException

from app.config import settings
from app.models import SecretCreate, SecretSummary, SecretUpdate

_client = SecretClient(vault_url=settings.key_vault_url, credential=DefaultAzureCredential())


def _new_id() -> str:
    return f"pw-{uuid.uuid4().hex}"


def _to_summary(secret_id: str, tags: dict) -> SecretSummary:
    return SecretSummary(
        id=secret_id,
        site=tags.get("site", ""),
        username=tags.get("username", ""),
        notes=tags.get("notes", ""),
        created_at=tags.get("created_at", ""),
    )


def list_mine(owner: str) -> list[SecretSummary]:
    summaries = []
    for props in _client.list_properties_of_secrets():
        if not props.enabled:
            continue
        tags = props.tags or {}
        if tags.get("owner") == owner:
            summaries.append(_to_summary(props.name, tags))
    summaries.sort(key=lambda s: s.created_at, reverse=True)
    return summaries


def create(owner: str, data: SecretCreate) -> str:
    secret_id = _new_id()
    tags = {
        "owner": owner,
        "site": data.site,
        "username": data.username,
        "notes": data.notes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _client.set_secret(secret_id, data.password, tags=tags)
    return secret_id


def _fetch_owned(secret_id: str, owner: str):
    try:
        secret = _client.get_secret(secret_id)
    except ResourceNotFoundError:
        raise HTTPException(status_code=404, detail="Not found")
    tags = secret.properties.tags or {}
    if tags.get("owner") != owner:
        raise HTTPException(status_code=403, detail="Forbidden")
    return secret, tags


def reveal(secret_id: str, owner: str) -> str:
    secret, _ = _fetch_owned(secret_id, owner)
    return secret.value


def get_summary(secret_id: str, owner: str) -> SecretSummary:
    _, tags = _fetch_owned(secret_id, owner)
    return _to_summary(secret_id, tags)


def update(secret_id: str, owner: str, data: SecretUpdate) -> None:
    _, tags = _fetch_owned(secret_id, owner)
    tags = {
        **tags,
        "site": data.site,
        "username": data.username,
        "notes": data.notes,
    }
    if data.password:
        _client.set_secret(secret_id, data.password, tags=tags)
    else:
        _client.update_secret_properties(secret_id, tags=tags)


def delete(secret_id: str, owner: str) -> None:
    _fetch_owned(secret_id, owner)
    _client.begin_delete_secret(secret_id)
