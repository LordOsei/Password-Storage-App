from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.config import settings

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
# /.auth/logout is served by Easy Auth, which only exists on App Service, so hide the link in dev mode.
templates.env.globals["auth_mode"] = lambda: settings.auth_mode
