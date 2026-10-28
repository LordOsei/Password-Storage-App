from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse

from app import keyvault
from app.auth import get_current_user
from app.models import SecretCreate, SecretUpdate

router = APIRouter(prefix="/secrets")


@router.post("")
def create_secret(
    site: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    notes: str = Form(""),
    user: str = Depends(get_current_user),
):
    keyvault.create(user, SecretCreate(site=site, username=username, password=password, notes=notes))
    return RedirectResponse(url="/", status_code=303)


@router.get("/{secret_id}/reveal")
def reveal_secret(secret_id: str, user: str = Depends(get_current_user)):
    return {"password": keyvault.reveal(secret_id, user)}


@router.post("/{secret_id}/update")
def update_secret(
    secret_id: str,
    site: str = Form(...),
    username: str = Form(...),
    password: str = Form(""),
    notes: str = Form(""),
    user: str = Depends(get_current_user),
):
    keyvault.update(secret_id, user, SecretUpdate(site=site, username=username, password=password, notes=notes))
    return RedirectResponse(url="/", status_code=303)


@router.post("/{secret_id}/delete")
def delete_secret(secret_id: str, user: str = Depends(get_current_user)):
    keyvault.delete(secret_id, user)
    return RedirectResponse(url="/", status_code=303)
