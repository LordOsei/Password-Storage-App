from fastapi import HTTPException, Request

from app.config import settings


def get_current_user(request: Request) -> str:
    if settings.auth_mode == "dev":
        return settings.local_dev_user

    user = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user
