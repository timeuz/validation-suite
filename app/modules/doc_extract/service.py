import asyncio
import hashlib
import ipaddress
import json
import logging
import zlib
from collections.abc import Iterable
from functools import lru_cache
from pathlib import PurePath
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx
import lxml.etree  # type: ignore[import-untyped]
import pymupdf
import pymupdf4llm  # type: ignore[import-untyped]
import tiktoken
import trafilatura
from fastapi import UploadFile
from pydantic import ValidationError
from redis.asyncio import Redis
from redis.exceptions import RedisError
from trafilatura.utils import decode_file

from app.core.exceptions import AppError
from app.core.ssrf import validate_url
from app.modules.doc_extract.schemas import (
    PdfExtractOptions,
    PdfExtractResponse,
    PdfMetadata,
    PdfUploadMetadata,
    SupportedEncoding,
    UrlExtractRequest,
    UrlExtractResponse,
    WebMetadata,
)

logger = logging.getLogger(__name__)

MAX_WEB_BYTES = 5 * 1024 * 1024  # 5 MiB strict ceiling
MAX_PDF_BYTES = 10 * 1024 * 1024  # 10 MiB strict ceiling
MAX_PDF_PAGES = 50
MAX_REDIRECTS = 5
READ_CHUNK_SIZE = 64 * 1024
HTTP_TIMEOUT_SECONDS = 15.0
HTTP_CONNECT_TIMEOUT_SECONDS = 5.0
TOTAL_FETCH_TIMEOUT_SECONDS = 45.0
REDIS_OP_TIMEOUT_SECONDS = 2.0
URL_CACHE_TTL_SECONDS = 3600
URL_CACHE_PREFIX = "doc_extract:url:v1:"
USER_AGENT = "ValidationSuite-DocExtract/1.0"
_DEFLATE_FALLBACK_BUFFER_LIMIT = 64

_NON_PUBLIC_V6_NETWORKS = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("::ffff:0:0:0/96"),
    ipaddress.IPv6Network("fec0::/10"),
)

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
ALLOWED_WEB_CONTENT_TYPES = {
    "",
    "text/html",
    "application/xhtml+xml",
    "text/plain",
    "text/markdown",
    "text/x-markdown",
    "application/xml",
    "text/xml",
}


class _PinnedDNSBackend(httpcore.AsyncNetworkBackend):
    """Connects only to pre-validated public IPs to prevent DNS rebinding."""

    def __init__(
        self,
        expected_host: str,
        allowed_ips: list[str],
        inner: httpcore.AsyncNetworkBackend,
    ) -> None:
        self._expected_host = expected_host.lower()
        self._allowed_ips = list(allowed_ips)
        self._inner = inner

    async def connect_tcp(
        self,
        host: str,
        port: int,
        # Parameter name required by httpcore.AsyncNetworkBackend interface.
        timeout: float | None = None,  # noqa: ASYNC109
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.lower() != self._expected_host or not self._allowed_ips:
            raise httpcore.ConnectError(f"Blocked unvalidated host connection: {host}")

        last_exc: Exception | None = None
        for ip in self._allowed_ips:
            try:
                return await self._inner.connect_tcp(
                    ip,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc

        assert last_exc is not None
        raise last_exc

    async def connect_unix_socket(
        self,
        path: str,
        # Parameter name required by httpcore.AsyncNetworkBackend interface.
        timeout: float | None = None,  # noqa: ASYNC109
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix socket connections are not allowed.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _build_pinned_transport(
    expected_host: str,
    public_ips: list[str],
) -> httpx.AsyncHTTPTransport:
    transport = httpx.AsyncHTTPTransport(trust_env=False)
    transport._pool._network_backend = _PinnedDNSBackend(
        expected_host=expected_host,
        allowed_ips=public_ips,
        inner=transport._pool._network_backend,
    )
    return transport


class _NonClosingTransport(httpx.AsyncBaseTransport):
    """Keeps caller-provided transports open across per-hop redirect clients."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        return None


def _is_non_public_ip(raw_ip: str) -> bool:
    ip = ipaddress.ip_address(raw_ip)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.is_site_local or any(ip in net for net in _NON_PUBLIC_V6_NETWORKS):
            return True
    return not ip.is_global or ip.is_multicast


async def _validate_public_url(raw_url: str) -> tuple[str, list[str]]:
    if not raw_url or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_url):
        raise AppError(400, "invalid_url", "URL contains invalid control characters.")

    try:
        split = urlsplit(raw_url)
        explicit_port = split.port
    except ValueError as exc:
        raise AppError(400, "invalid_url", "Malformed URL.") from exc

    if split.scheme.lower() not in {"http", "https"} or not split.netloc:
        raise AppError(400, "invalid_url", "Only http(s) URLs with a host are allowed.")

    if "@" in split.netloc:
        raise AppError(400, "invalid_url", "Credentials in URL are not allowed.")

    if explicit_port == 0:
        raise AppError(400, "ssrf_blocked", "Port 0 is not allowed.")

    try:
        httpx_parsed = httpx.URL(raw_url)
    except httpx.InvalidURL as exc:
        raise AppError(400, "invalid_url", "Malformed URL.") from exc

    if not httpx_parsed.raw_host:
        raise AppError(400, "invalid_url", "Malformed URL.")

    try:
        validated_url, public_ips = await validate_url(raw_url)
    except ValueError as exc:
        raise AppError(400, "invalid_url", "Malformed URL.") from exc

    if any(_is_non_public_ip(ip) for ip in public_ips):
        raise AppError(400, "ssrf_blocked", "Target resolves to a non-public address.")

    return validated_url, public_ips


@lru_cache(maxsize=8)
def _get_tiktoken_encoding(encoding_name: str) -> tiktoken.Encoding:
    return tiktoken.get_encoding(encoding_name)


def count_tokens(text: str, encoding_name: SupportedEncoding = "cl100k_base") -> int:
    """Count tiktoken tokens for text using the given encoding."""
    if not text:
        return 0
    enc = _get_tiktoken_encoding(encoding_name)
    return len(enc.encode(text, disallowed_special=()))


def _build_url_cache_key(req: UrlExtractRequest) -> str:
    canonical = json.dumps(
        {
            "url": req.url,
            "output_format": req.output_format,
            "include_links": req.include_links,
            "include_tables": req.include_tables,
            "include_comments": req.include_comments,
            "favor_precision": req.favor_precision,
            "favor_recall": req.favor_recall,
            "encoding": req.encoding,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{URL_CACHE_PREFIX}{digest}"


def _parse_content_length(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    try:
        parsed = int(raw_value.strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _parse_content_encodings(raw_header: str | None) -> str:
    if not raw_header:
        return "identity"
    parts = [part.strip().lower() for part in raw_header.split(",") if part.strip()]
    non_identity = [part for part in parts if part != "identity"]
    if not non_identity:
        return "identity"
    if len(non_identity) == 1 and non_identity[0] in {"gzip", "x-gzip", "deflate"}:
        return "gzip" if non_identity[0] == "x-gzip" else non_identity[0]
    raise AppError(
        502,
        "upstream_error",
        f"Unsupported Content-Encoding '{raw_header}'.",
    )


def _payload_too_large_error(
    subject: str,
    max_bytes: int,
    *,
    extra_details: dict[str, int] | None = None,
) -> AppError:
    details: dict[str, int] = {"max_bytes": max_bytes}
    if extra_details:
        details.update(extra_details)
    return AppError(
        413,
        "payload_too_large",
        f"{subject} exceeds maximum allowed size of {max_bytes} bytes.",
        details=details,
    )


class _BoundedZlibDecoder:
    """Incrementally decompresses gzip/deflate chunks under a strict byte ceiling."""

    def __init__(self, encoding: str, max_bytes: int) -> None:
        self._encoding = encoding
        self._max_bytes = max_bytes
        self._allow_raw_deflate_fallback = encoding == "deflate"
        self._has_output = False
        self._initial_buffer = bytearray()
        wbits = zlib.MAX_WBITS | 16 if encoding == "gzip" else zlib.MAX_WBITS
        self._decompressor = zlib.decompressobj(wbits)

    def feed(self, chunk: bytes, buf: bytearray) -> None:
        pending = chunk
        while pending:
            remaining = self._max_bytes - len(buf)
            step_limit = min(remaining + 1, READ_CHUNK_SIZE)
            decoded, pending = self._decompress_step(pending, step_limit)
            if decoded:
                self._has_output = True
                self._allow_raw_deflate_fallback = False
                self._initial_buffer.clear()
            if len(decoded) > remaining:
                raise _payload_too_large_error("Response", self._max_bytes)
            buf.extend(decoded)
            if self._encoding == "gzip" and self._decompressor.eof:
                self._decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)

    def _decompress_step(self, pending: bytes, step_limit: int) -> tuple[bytes, bytes]:
        try:
            decoded = self._decompressor.decompress(pending, max_length=step_limit)
        except zlib.error as exc:
            if not self._allow_raw_deflate_fallback or self._has_output:
                raise AppError(
                    502,
                    "upstream_error",
                    "Failed to decode compressed upstream response.",
                ) from exc
            self._allow_raw_deflate_fallback = False
            replay = bytes(self._initial_buffer) + pending
            self._initial_buffer.clear()
            self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                decoded = self._decompressor.decompress(replay, max_length=step_limit)
            except zlib.error as inner_exc:
                raise AppError(
                    502,
                    "upstream_error",
                    "Failed to decode compressed upstream response.",
                ) from inner_exc
            next_pending = self._decompressor.unconsumed_tail
            if not decoded and next_pending == replay:
                return decoded, b""
            return decoded, next_pending

        if self._encoding == "gzip" and self._decompressor.eof:
            next_pending = (
                self._decompressor.unused_data or self._decompressor.unconsumed_tail
            )
            return decoded, next_pending

        next_pending = self._decompressor.unconsumed_tail
        if self._allow_raw_deflate_fallback and not decoded:
            consumed_len = len(pending) - len(next_pending)
            if len(self._initial_buffer) + consumed_len <= (
                _DEFLATE_FALLBACK_BUFFER_LIMIT
            ):
                self._initial_buffer.extend(pending[:consumed_len])
            else:
                self._allow_raw_deflate_fallback = False
                self._initial_buffer.clear()

        if not decoded and next_pending == pending:
            return decoded, b""
        return decoded, next_pending

    def flush(self, buf: bytearray) -> None:
        try:
            flushed = self._decompressor.flush()
        except zlib.error as exc:
            raise AppError(
                502,
                "upstream_error",
                "Failed to decode compressed upstream response.",
            ) from exc
        if len(buf) + len(flushed) > self._max_bytes:
            raise _payload_too_large_error("Response", self._max_bytes)
        buf.extend(flushed)


async def _read_bounded_response(
    response: httpx.Response,
    max_bytes: int = MAX_WEB_BYTES,
) -> bytes:
    if hasattr(response, "_content"):
        buffered = response.content
        if len(buffered) > max_bytes:
            raise _payload_too_large_error("Response", max_bytes)
        return buffered

    encoding = _parse_content_encodings(response.headers.get("content-encoding"))
    decoder = (
        _BoundedZlibDecoder(encoding, max_bytes) if encoding != "identity" else None
    )

    buf = bytearray()
    async for raw_chunk in response.aiter_raw(chunk_size=READ_CHUNK_SIZE):
        if response.num_bytes_downloaded > max_bytes:
            raise _payload_too_large_error("Response", max_bytes)
        if decoder is not None:
            decoder.feed(raw_chunk, buf)
            continue
        if len(buf) + len(raw_chunk) > max_bytes:
            raise _payload_too_large_error("Response", max_bytes)
        buf.extend(raw_chunk)

    if decoder is not None:
        decoder.flush(buf)

    return bytes(buf)


def _extract_content_type(response: httpx.Response) -> str:
    return response.headers.get("content-type", "").split(";")[0].strip().lower()


def _ensure_fetchable_response(response: httpx.Response) -> str:
    if response.status_code >= 400:
        raise AppError(
            502,
            "upstream_http_error",
            f"Upstream server returned HTTP {response.status_code}.",
            details={"upstream_status": response.status_code},
        )
    if 300 <= response.status_code < 400:
        raise AppError(
            502,
            "upstream_http_error",
            f"Unsupported redirect status HTTP {response.status_code}.",
            details={"upstream_status": response.status_code},
        )

    content_type = _extract_content_type(response)
    if content_type not in ALLOWED_WEB_CONTENT_TYPES:
        raise AppError(
            415,
            "unsupported_media_type",
            f"Unsupported content type '{content_type}' for URL extraction.",
        )

    content_length = _parse_content_length(response.headers.get("content-length"))
    if content_length is not None and content_length > MAX_WEB_BYTES:
        raise _payload_too_large_error(
            "Response",
            MAX_WEB_BYTES,
            extra_details={"content_length": content_length},
        )
    return content_type


async def _fetch_hop(
    url: str,
    public_ips: list[str],
    *,
    headers: dict[str, str],
    request_timeout: httpx.Timeout,
    transport: httpx.AsyncBaseTransport | None,
) -> tuple[str | None, bytes | None, str, str | None]:
    try:
        parsed_url = httpx.URL(url)
    except httpx.InvalidURL as exc:
        raise AppError(400, "invalid_url", "Malformed URL.") from exc

    if not parsed_url.raw_host:
        raise AppError(400, "invalid_url", "Malformed URL.")

    expected_host = parsed_url.raw_host.decode("ascii").lower()
    active_transport = (
        _NonClosingTransport(transport)
        if transport is not None
        else _build_pinned_transport(expected_host, public_ips)
    )

    try:
        async with (
            httpx.AsyncClient(
                transport=active_transport,
                timeout=request_timeout,
                follow_redirects=False,
                trust_env=False,
                headers=headers,
            ) as client,
            client.stream("GET", url) as response,
        ):
            if response.status_code in REDIRECT_STATUS_CODES:
                location = response.headers.get("location")
                if not location or not location.strip():
                    raise AppError(
                        502,
                        "upstream_error",
                        "Redirect response missing Location header.",
                    )
                return urljoin(url, location.strip()), None, "", None

            content_type = _ensure_fetchable_response(response)
            raw_bytes = await _read_bounded_response(response, max_bytes=MAX_WEB_BYTES)
            return None, raw_bytes, content_type, response.charset_encoding
    except AppError:
        raise
    except httpx.TimeoutException as exc:
        raise AppError(
            504, "upstream_timeout", "Timed out while fetching target URL."
        ) from exc
    except httpx.InvalidURL as exc:
        raise AppError(400, "invalid_url", "Malformed redirect URL.") from exc
    except httpx.RequestError as exc:
        raise AppError(
            502,
            "upstream_error",
            f"Failed to fetch target URL: {type(exc).__name__}.",
        ) from exc


async def _fetch_url_bytes(
    initial_url: str,
    initial_ips: list[str],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[str, bytes, str, str | None]:
    current_url = initial_url
    current_ips = initial_ips
    timeout = httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_CONNECT_TIMEOUT_SECONDS)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    }

    try:
        async with asyncio.timeout(TOTAL_FETCH_TIMEOUT_SECONDS):
            for hop in range(MAX_REDIRECTS + 1):
                if hop > 0:
                    current_url, current_ips = await _validate_public_url(current_url)

                redirect_url, raw_bytes, content_type, charset = await _fetch_hop(
                    current_url,
                    current_ips,
                    headers=headers,
                    request_timeout=timeout,
                    transport=transport,
                )
                if redirect_url is not None:
                    current_url = redirect_url
                    continue

                assert raw_bytes is not None
                return current_url, raw_bytes, content_type, charset
    except TimeoutError as exc:
        raise AppError(
            504, "upstream_timeout", "Timed out while fetching target URL."
        ) from exc

    raise AppError(
        400,
        "too_many_redirects",
        f"Exceeded maximum of {MAX_REDIRECTS} redirects.",
    )


def _sanitize_text(text: str) -> str:
    return text.encode("utf-8", errors="replace").decode("utf-8")


def _decode_html(raw_bytes: bytes, header_charset: str | None) -> str:
    if header_charset:
        try:
            return raw_bytes.decode(header_charset, errors="replace").lstrip("\ufeff")
        except LookupError:
            pass
    decoded = decode_file(raw_bytes)
    if isinstance(decoded, bytes):
        text = decoded.decode("utf-8", errors="replace")
    else:
        text = _sanitize_text(decoded)
    return text.lstrip("\ufeff")


def _clean_opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = _sanitize_text(str(value)).strip()
    return text or None


def _extract_web_sync(
    raw_bytes: bytes,
    final_url: str,
    content_type: str,
    header_charset: str | None,
    req: UrlExtractRequest,
) -> tuple[str, WebMetadata, int]:
    html_text = _decode_html(raw_bytes, header_charset)

    if content_type in {"text/plain", "text/markdown", "text/x-markdown"}:
        content = _sanitize_text(html_text).strip()
        if not content:
            raise AppError(
                422, "extraction_empty", "No extractable content found at URL."
            )
        return content, WebMetadata(), count_tokens(content, req.encoding)

    try:
        extracted = trafilatura.extract(
            html_text,
            url=final_url,
            output_format=req.output_format,
            include_links=req.include_links,
            include_tables=req.include_tables,
            include_comments=req.include_comments,
            favor_precision=req.favor_precision,
            favor_recall=req.favor_recall,
        )
    except (
        ValueError,
        RuntimeError,
        TypeError,
        UnicodeError,
        RecursionError,
        lxml.etree.Error,
    ) as exc:
        raise AppError(
            422, "extraction_failed", f"Failed to parse HTML content: {exc}"
        ) from exc

    if not extracted or not extracted.strip():
        raise AppError(422, "extraction_empty", "No extractable content found at URL.")

    content = _sanitize_text(extracted).strip()

    metadata = WebMetadata()
    try:
        meta_doc = trafilatura.extract_metadata(html_text, default_url=final_url)
        if meta_doc is not None:
            metadata = WebMetadata(
                title=_clean_opt_str(meta_doc.title),
                author=_clean_opt_str(meta_doc.author),
                date=_clean_opt_str(meta_doc.date),
                sitename=_clean_opt_str(meta_doc.sitename),
                language=_clean_opt_str(meta_doc.language),
                description=_clean_opt_str(meta_doc.description),
            )
    except Exception:
        logger.debug(
            "Failed to extract optional web metadata for %s",
            final_url,
            exc_info=True,
        )

    token_count = count_tokens(content, req.encoding)
    return content, metadata, token_count


async def extract_url(
    req: UrlExtractRequest,
    redis_client: Redis | None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> UrlExtractResponse:
    """Validate URL against SSRF, fetch bounded body, extract text, and cache."""
    validated_url, public_ips = await _validate_public_url(req.url)
    cache_key = _build_url_cache_key(req)

    if req.use_cache and redis_client is not None:
        try:
            cached_raw = await asyncio.wait_for(
                redis_client.get(cache_key),
                timeout=REDIS_OP_TIMEOUT_SECONDS,
            )
            if cached_raw:
                cached_resp = UrlExtractResponse.model_validate_json(cached_raw)
                return cached_resp.model_copy(update={"cached": True})
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("Redis GET failed for %s: %s", cache_key, exc)
        except (ValidationError, ValueError):
            logger.warning("Corrupted Redis cache entry ignored for %s", cache_key)

    final_url, raw_bytes, content_type, header_charset = await _fetch_url_bytes(
        validated_url,
        public_ips,
        transport=transport,
    )

    content, metadata, token_count = await asyncio.to_thread(
        _extract_web_sync,
        raw_bytes,
        final_url,
        content_type,
        header_charset,
        req,
    )

    response = UrlExtractResponse(
        url=req.url,
        final_url=final_url,
        content=content,
        output_format=req.output_format,
        char_count=len(content),
        token_count=token_count,
        encoding=req.encoding,
        cached=False,
        metadata=metadata,
    )

    if redis_client is not None:
        try:
            await asyncio.wait_for(
                redis_client.set(
                    cache_key,
                    response.model_dump_json(),
                    ex=URL_CACHE_TTL_SECONDS,
                ),
                timeout=REDIS_OP_TIMEOUT_SECONDS,
            )
        except (RedisError, OSError, TimeoutError) as exc:
            logger.warning("Redis SET failed for %s: %s", cache_key, exc)

    return response


def _sanitize_filename(filename: str | None) -> str:
    raw = _sanitize_text(filename or "").replace("\\", "/").strip()
    raw = "".join(ch for ch in raw if ord(ch) >= 32 and ord(ch) != 127)
    cleaned = PurePath(raw).name if raw else ""
    if cleaned in {"", ".", ".."}:
        cleaned = "document.pdf"
    return cleaned[:255]


async def _read_upload_limited(
    file: UploadFile,
    max_bytes: int = MAX_PDF_BYTES,
) -> bytes:
    try:
        if file.size is not None and file.size > max_bytes:
            raise _payload_too_large_error(
                "PDF",
                max_bytes,
                extra_details={"size_bytes": file.size},
            )

        buf = bytearray()
        while True:
            chunk = await file.read(READ_CHUNK_SIZE)
            if not chunk:
                break
            if len(buf) + len(chunk) > max_bytes:
                raise _payload_too_large_error("PDF", max_bytes)
            buf.extend(chunk)
        return bytes(buf)
    finally:
        await file.close()


def _extract_pdf_sync(
    pdf_bytes: bytes,
    encoding: SupportedEncoding,
) -> tuple[str, int, PdfMetadata, int]:
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    except (pymupdf.FileDataError, RuntimeError, ValueError) as exc:
        raise AppError(400, "invalid_pdf", "Corrupted or unreadable PDF file.") from exc

    try:
        if doc.needs_pass:
            raise AppError(
                422,
                "encrypted_pdf",
                "Encrypted or password-protected PDFs are not supported.",
            )

        page_count = doc.page_count
        if page_count <= 0:
            raise AppError(400, "invalid_pdf", "PDF document contains no pages.")

        if page_count > MAX_PDF_PAGES:
            raise AppError(
                422,
                "page_limit_exceeded",
                f"PDF has {page_count} pages, exceeding the limit of "
                f"{MAX_PDF_PAGES} pages.",
                details={"page_count": page_count, "max_pages": MAX_PDF_PAGES},
            )

        raw_meta = doc.metadata or {}
        metadata = PdfMetadata(
            title=_clean_opt_str(raw_meta.get("title")),
            author=_clean_opt_str(raw_meta.get("author")),
            subject=_clean_opt_str(raw_meta.get("subject")),
            creator=_clean_opt_str(raw_meta.get("creator")),
            producer=_clean_opt_str(raw_meta.get("producer")),
        )

        try:
            markdown = pymupdf4llm.to_markdown(
                doc,
                write_images=False,
                embed_images=False,
                show_progress=False,
                use_ocr=False,
            )
        except pymupdf.FileDataError as exc:
            raise AppError(
                400, "invalid_pdf", "Corrupted or unreadable PDF file."
            ) from exc
        except (
            RuntimeError,
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            ZeroDivisionError,
            OverflowError,
        ) as exc:
            raise AppError(
                422, "extraction_failed", f"Failed to extract PDF content: {exc}"
            ) from exc

        content = _sanitize_text(markdown or "").strip()
        token_count = count_tokens(content, encoding)
        return content, page_count, metadata, token_count
    finally:
        doc.close()


async def extract_pdf(
    file: UploadFile,
    options: PdfExtractOptions,
) -> PdfExtractResponse:
    """Extract structured Markdown and token count from an uploaded PDF."""
    pdf_bytes = await _read_upload_limited(file, max_bytes=MAX_PDF_BYTES)
    if not pdf_bytes:
        raise AppError(400, "empty_file", "Uploaded PDF file is empty.")

    upload_meta = PdfUploadMetadata(
        filename=_sanitize_filename(file.filename),
        content_type=file.content_type,
        size_bytes=len(pdf_bytes),
    )

    if b"%PDF-" not in pdf_bytes[:1024]:
        raise AppError(400, "invalid_pdf", "Uploaded file is not a valid PDF document.")

    content, page_count, metadata, token_count = await asyncio.to_thread(
        _extract_pdf_sync,
        pdf_bytes,
        options.encoding,
    )

    return PdfExtractResponse(
        filename=upload_meta.filename,
        content=content,
        page_count=page_count,
        size_bytes=upload_meta.size_bytes,
        char_count=len(content),
        token_count=token_count,
        encoding=options.encoding,
        metadata=metadata,
    )
