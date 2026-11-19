import os

from fastapi import APIRouter, Depends, Request

from app import keyvault
from app.auth import get_current_user
from app.config import settings
from app.templating import templates

router = APIRouter()


@router.get("/welcome")
def welcome(request: Request):
    # Deliberately public (Easy Auth excludes this path) so link-preview bots can read its
    # Open Graph tags. It must not depend on get_current_user or show any account data.
    # Build absolute preview URLs from App Service's trusted hostname, never from the client's
    # Host header. Only local dev falls back to the request URL; otherwise use relative URLs.
    host = os.environ.get("WEBSITE_HOSTNAME")
    if host:
        base_url = f"https://{host}"
    elif settings.auth_mode == "dev":
        base_url = str(request.base_url).rstrip("/")
    else:
        base_url = ""
    sign_in_url = "/.auth/login/aad?post_login_redirect_uri=/" if settings.auth_mode == "header" else "/"
    return templates.TemplateResponse(
        request, "welcome.html", {"base_url": base_url, "sign_in_url": sign_in_url}
    )


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
