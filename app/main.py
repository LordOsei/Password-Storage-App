from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.routes import pages, secrets

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
    "Referrer-Policy": "no-referrer",
}


def _is_cross_site(request: Request) -> bool:
    # Modern browsers send Sec-Fetch-Site; fall back to comparing Origin with Host.
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site is not None:
        return fetch_site not in ("same-origin", "none")
    origin = request.headers.get("origin")
    if origin is not None:
        return urlsplit(origin).netloc != request.headers.get("host")
    return False


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.method not in SAFE_METHODS and _is_cross_site(request):
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
