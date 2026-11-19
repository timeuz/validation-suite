from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.exceptions import RequestIDMiddleware, register_exception_handlers
from app.core.redis_client import close_redis
from app.core.security import RapidAPIProxyMiddleware
from app.modules.doc_extract.router import router as extract_router
from app.modules.mail_verify.router import router as mail_router
from app.modules.sec_audit.router import router as sec_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await close_redis()


app = FastAPI(title="Validation Suite", lifespan=lifespan)

# Ordem: o último adicionado é o mais externo -> RequestID envolve tudo.
app.add_middleware(RapidAPIProxyMiddleware)
app.add_middleware(RequestIDMiddleware)
register_exception_handlers(app)

app.include_router(sec_router, prefix="/v1", tags=["Security"])
app.include_router(mail_router, prefix="/v1/email", tags=["Email"])
app.include_router(extract_router, prefix="/v1/extract", tags=["Extract"])


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}
