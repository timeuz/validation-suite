from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile
from redis.asyncio import Redis

from app.core.redis_client import get_redis
from app.modules.doc_extract.schemas import (
    PdfExtractOptions,
    PdfExtractResponse,
    SupportedEncoding,
    UrlExtractRequest,
    UrlExtractResponse,
)
from app.modules.doc_extract.service import extract_pdf, extract_url

router = APIRouter()


def _pdf_options(
    encoding: Annotated[
        SupportedEncoding,
        Form(description="tiktoken encoding used to count tokens."),
    ] = "cl100k_base",
) -> PdfExtractOptions:
    return PdfExtractOptions(encoding=encoding)


@router.post(
    "/url",
    response_model=UrlExtractResponse,
    summary="Extract web page content and count tokens",
)
async def extract_url_endpoint(
    payload: UrlExtractRequest,
    redis_client: Annotated[Redis, Depends(get_redis)],
) -> UrlExtractResponse:
    """Extract clean web page content and token count from a public URL."""
    return await extract_url(payload, redis_client)


@router.post(
    "/pdf",
    response_model=PdfExtractResponse,
    summary="Extract structured Markdown from a PDF and count tokens",
)
async def extract_pdf_endpoint(
    file: Annotated[
        UploadFile,
        File(description="PDF document (max 10MB, max 50 pages)."),
    ],
    options: Annotated[PdfExtractOptions, Depends(_pdf_options)],
) -> PdfExtractResponse:
    """Extract structured Markdown and token count from an uploaded PDF."""
    return await extract_pdf(file, options)
