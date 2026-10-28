from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.routes import pages, secrets

app = FastAPI(title="Password Store")

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

app.include_router(pages.router)
app.include_router(secrets.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
