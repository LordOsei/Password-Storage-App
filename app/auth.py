import logging

from fastapi import HTTPException, Request

from app.config import settings

logger = logging.getLogger("app.security")


class NotAuthenticated(Exception):
    """No signed-in user. app.main turns this into a redirect to /welcome (page loads) or a 401."""


def get_current_user(request: Request) -> str:
    if settings.auth_mode == "dev":
        return settings.local_dev_user

    # Easy Auth runs with unauthenticatedClientAction=AllowAnonymous so signed-out visitors can
    # reach /welcome. That makes this check the gatekeeper for every other route. It relies on
    # Easy Auth stripping client-supplied X-MS-CLIENT-PRINCIPAL-* headers and injecting them only
    # for signed-in users. The object-ID allowlist is our own check on top of Easy Auth's
    # allowedPrincipals, so a signed-in but unlisted account is refused even if that is skipped.
    user = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
    oid = request.headers.get("X-MS-CLIENT-PRINCIPAL-ID", "").strip().lower()
    if not user or not oid:
        raise NotAuthenticated()
    if oid not in settings.allowed_ids:
        logger.warning("Refused signed-in user not on ALLOWED_OBJECT_IDS: oid=%s", oid)
        raise HTTPException(status_code=403, detail="Your account is not allowed to use this app")
    return user
