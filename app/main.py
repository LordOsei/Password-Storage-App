import logging
import os
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.routes import pages, secrets

logger = logging.getLogger("app.security")

app = FastAPI(title="Password Store")

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.include_router(pages.router)
app.include_router(secrets.router)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # "same-origin" (not "no-referrer") so browsers send the real Origin on our own form POSTs;
    # with "no-referrer" they send "Origin: null", which the cross-site check must reject.
    "Referrer-Policy": "same-origin",
}


def _own_hosts(request: Request) -> set[str]:
    # Behind App Service's front end and Easy Auth proxy, Host may not be the public hostname,
    # so also accept the forwarded host and the hostname App Service sets for the site.
    hosts = {
        request.headers.get("host", ""),
        request.headers.get("x-forwarded-host", "").split(",")[0].strip(),
        os.environ.get("WEBSITE_HOSTNAME", ""),
    }
    return {h.lower() for h in hosts if h}


def _is_cross_site(request: Request) -> bool:
    # Modern browsers send Sec-Fetch-Site; fall back to comparing Origin with our own host.
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site not in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is not None:
        return urlsplit(origin).netloc.lower() not in _own_hosts(request)
    return False


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.method not in SAFE_METHODS and _is_cross_site(request):
        logger.warning(
            "Blocked cross-site %s %s: sec-fetch-site=%r origin=%r host=%r x-forwarded-host=%r",
            request.method, request.url.path,
            request.headers.get("sec-fetch-site"), request.headers.get("origin"),
            request.headers.get("host"), request.headers.get("x-forwarded-host"),
        )
        return PlainTextResponse("Cross-site request blocked", status_code=403)

    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    if not request.url.path.startswith("/static/"):
        # Pages and the reveal endpoint carry account data; keep them out of browser/proxy caches.
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
