from fastapi import APIRouter, Depends, Request

from app import keyvault
from app.auth import get_current_user
from app.templating import templates

router = APIRouter()


@router.get("/")
def index(request: Request, user: str = Depends(get_current_user)):
    secrets = keyvault.list_mine(user)
    return templates.TemplateResponse(
        request, "index.html", {"secrets": secrets, "user": user}
    )


@router.get("/add")
def add_form(request: Request, user: str = Depends(get_current_user)):
    return templates.TemplateResponse(request, "add.html", {"user": user})


@router.get("/secrets/{secret_id}/edit")
def edit_form(request: Request, secret_id: str, user: str = Depends(get_current_user)):
    summary = keyvault.get_summary(secret_id, user)
    return templates.TemplateResponse(
        request, "edit.html", {"secret": summary, "user": user}
    )
