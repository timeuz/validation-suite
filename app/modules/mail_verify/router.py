import redis.asyncio as redis
from fastapi import APIRouter, Depends

from app.core.redis_client import get_redis
from app.modules.mail_verify.schemas import EmailVerifyRequest, EmailVerifyResponse
from app.modules.mail_verify.service import verify_email

router = APIRouter()


@router.post("/verify", response_model=EmailVerifyResponse)
async def verify_email_endpoint(
    payload: EmailVerifyRequest,
    redis_client: redis.Redis = Depends(get_redis),
) -> EmailVerifyResponse:
    """Verifica sintaxe, registros DNS (MX, SPF, DMARC), reputação e blocklist de descartáveis."""
    return await verify_email(payload.email, redis_client=redis_client)

