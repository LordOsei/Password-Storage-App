from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from pydantic import ValidationError

from app import keyvault
from app.auth import get_current_user
from app.models import SecretCreate, SecretUpdate
from app.templating import templates

router = APIRouter(prefix="/secrets")


def _error_messages(exc: ValidationError) -> list[str]:
    return [f"{str(err['loc'][0]).capitalize()}: {err['msg']}" for err in exc.errors()]


@router.post("")
def create_secret(
    request: Request,
    site: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    notes: str = Form(""),
    user: str = Depends(get_current_user),
):
    try:
        data = SecretCreate(site=site, username=username, password=password, notes=notes)
    except ValidationError as exc:
        # Re-render with what was typed (except the password, which is never echoed back).
        return templates.TemplateResponse(
            request, "add.html",
            {"user": user, "errors": _error_messages(exc), "form": {"site": site, "username": username, "notes": notes}},
            status_code=422,
        )
    keyvault.create(user, data)
    return RedirectResponse(url="/", status_code=303)


@router.get("/{secret_id}/reveal")
def reveal_secret(secret_id: str, user: str = Depends(get_current_user)):
    return {"password": keyvault.reveal(secret_id, user)}


@router.post("/{secret_id}/update")
def update_secret(
    request: Request,
    secret_id: str,
    site: str = Form(...),
    username: str = Form(...),
    password: str = Form(""),
    notes: str = Form(""),
    user: str = Depends(get_current_user),
):
    try:
        data = SecretUpdate(site=site, username=username, password=password, notes=notes)
    except ValidationError as exc:
        keyvault.get_summary(secret_id, user)  # ownership check before rendering anything about this entry
        return templates.TemplateResponse(
            request, "edit.html",
            {
                "user": user,
                "errors": _error_messages(exc),
                "secret": {"id": secret_id, "site": site, "username": username, "notes": notes},
            },
            status_code=422,
        )
    keyvault.update(secret_id, user, data)
    return RedirectResponse(url="/", status_code=303)


@router.post("/{secret_id}/delete")
def delete_secret(secret_id: str, user: str = Depends(get_current_user)):
    keyvault.delete(secret_id, user)
    return RedirectResponse(url="/", status_code=303)
