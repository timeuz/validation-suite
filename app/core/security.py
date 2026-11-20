import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.config import get_settings
from app.core.exceptions import error_response


class RapidAPIProxyMiddleware(BaseHTTPMiddleware):
    """Bloqueia tudo que não venha do gateway da RapidAPI (falha fechado)."""

    async def dispatch(self, request: Request, call_next):
        s = get_settings()
        if request.url.path in s.public_paths:
            return await call_next(request)
        provided = request.headers.get("X-RapidAPI-Proxy-Secret", "")
        secrets = s.proxy_secrets
        # sem curto-circuito: tempo constante em relação a qual secret bateu
        matches = [hmac.compare_digest(provided.encode(), x.encode()) for x in secrets]
        if not secrets or not any(matches):
            return error_response(request, 403, "forbidden", "Invalid or missing proxy secret.")
        return await call_next(request)
