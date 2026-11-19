from fastapi import APIRouter, Depends, status
import redis.asyncio as redis

from app.core.config import get_settings
from app.core.redis_client import get_redis
from app.modules.sec_audit.schemas import (
    AuditRequest,
    AuditResponse,
    FeedSyncResponse,
)
from app.modules.sec_audit.service import SecurityAuditService

router = APIRouter()


def get_audit_service(
    redis_client: redis.Redis = Depends(get_redis),
) -> SecurityAuditService:
    """FastAPI dependency injecting Redis-backed SecurityAuditService."""
    auth_key = get_settings().urlhaus_auth_key.strip()
    urlhaus_url = (
        f"https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/text_online/"
        if auth_key
        else None
    )
    return SecurityAuditService(redis_client=redis_client, urlhaus_url=urlhaus_url)


@router.post(
    "/audit",
    response_model=AuditResponse,
    status_code=status.HTTP_200_OK,
    summary="Perform a full security audit on a target URL",
)
async def audit_url(
    payload: AuditRequest,
    service: SecurityAuditService = Depends(get_audit_service),
) -> AuditResponse:
    return await service.audit(payload)


@router.post(
    "/audit/feeds/sync",
    response_model=FeedSyncResponse,
    status_code=status.HTTP_200_OK,
    summary="Synchronize URLhaus and OpenPhish threat feeds into Redis",
)
async def sync_feeds(
    service: SecurityAuditService = Depends(get_audit_service),
) -> FeedSyncResponse:
    return await service.sync_threat_feeds()
