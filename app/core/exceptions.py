import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class AppError(Exception):
    def __init__(self, status_code: int, code: str, message: str, details: object | None = None):
        self.status_code, self.code, self.message, self.details = status_code, code, message, details
        super().__init__(message)


def error_response(request: Request, status_code: int, code: str, message: str, details: object | None = None) -> JSONResponse:
    rid = getattr(request.state, "request_id", "-")
    body = {"error": {"code": code, "message": message, "details": details, "request_id": rid}}
    return JSONResponse(body, status_code=status_code, headers={"X-Request-ID": rid})


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app(request: Request, exc: AppError):
        return error_response(request, exc.status_code, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def _val(request: Request, exc: RequestValidationError):
        return error_response(request, 422, "validation_error", "Invalid request.", jsonable(exc.errors()))

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        return error_response(request, exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        return error_response(request, 500, "internal_error", "Internal server error.")


def jsonable(obj):
    from fastapi.encoders import jsonable_encoder
    return jsonable_encoder(obj)
