import asyncio
import gzip
import io
import shutil
import socket
import ssl
import subprocess
import sys
import tracemalloc
import zlib
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock

import httpcore
import httpx
import lxml.etree  # type: ignore[import-untyped]
import pymupdf
import pymupdf4llm  # type: ignore[import-untyped]
import pytest
import tiktoken
from fastapi import UploadFile
from redis.exceptions import RedisError

_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from app.core.config import get_settings  # noqa: E402
from app.core.redis_client import get_redis  # noqa: E402
from app.main import app  # noqa: E402
from app.modules.doc_extract import service  # noqa: E402
from app.modules.doc_extract.service import (  # noqa: E402
    MAX_PDF_BYTES,
    MAX_PDF_PAGES,
    MAX_WEB_BYTES,
    _PinnedDNSBackend,
)

PROXY_SECRET = "test-rapidapi-secret"
AUTH_HEADERS = {"X-RapidAPI-Proxy-Secret": PROXY_SECRET}


class FakeRedis:
    """In-memory async Redis stand-in for testing URL caching behavior."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int | None] = {}
        self.get_calls: int = 0
        self.set_calls: int = 0

    async def get(self, key: str) -> str | None:
        self.get_calls += 1
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.set_calls += 1
        self.store[key] = value
        self.ttls[key] = ex
        return True


def _make_pdf_bytes(
    pages: int = 1,
    *,
    text_per_page: str = "Structured PDF Content",
    title: str = "Sample Document",
    author: str = "Content Extractor",
    password: str | None = None,
    blank: bool = False,
) -> bytes:
    doc = pymupdf.open()
    doc.set_metadata({"title": title, "author": author, "subject": "Testing"})
    for idx in range(pages):
        page = doc.new_page()
        if not blank:
            page.insert_text(
                (72, 72), f"Heading Page {idx + 1}\n\n{text_per_page} #{idx + 1}."
            )
    if password:
        raw = doc.tobytes(
            encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw=password, owner_pw=password
        )
    else:
        raw = doc.tobytes()
    doc.close()
    return raw


@pytest.fixture(autouse=True)
def _configure_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RAPIDAPI_PROXY_SECRET", PROXY_SECRET)
    get_settings.cache_clear()
    yield
    app.dependency_overrides.clear()
    get_settings.cache_clear()


@pytest.fixture
def fake_redis() -> FakeRedis:
    redis = FakeRedis()
    app.dependency_overrides[get_redis] = lambda: redis
    return redis


# ---------------------------------------------------------------------------
# Security & Auth Middleware sanity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_proxy_secret_is_rejected():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/v1/extract/url", json={"url": "https://example.com"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "forbidden"


# ---------------------------------------------------------------------------
# SSRF Blocking Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("blocked_url", "expected_code"),
    [
        ("http://127.0.0.1/admin", "ssrf_blocked"),
        ("http://127.0.0.1:8080/metrics", "ssrf_blocked"),
        ("http://0.0.0.0/secret", "ssrf_blocked"),
        ("http://localhost/internal", "ssrf_blocked"),
        ("http://169.254.169.254/latest/meta-data/", "ssrf_blocked"),
        ("http://10.0.0.1/status", "ssrf_blocked"),
        ("http://172.16.0.5/private", "ssrf_blocked"),
        ("http://192.168.1.1/router", "ssrf_blocked"),
        ("http://[::1]/loopback", "ssrf_blocked"),
        ("http://[::ffff:127.0.0.1]/mapped", "ssrf_blocked"),
        ("http://93.184.216.34:22/", "ssrf_blocked"),
        ("ftp://93.184.216.34/file", "invalid_url"),
        ("file:///etc/passwd", "invalid_url"),
        ("http://user:pass@93.184.216.34/", "invalid_url"),
    ],
)
async def test_url_ssrf_and_invalid_schemes_blocked(
    blocked_url: str,
    expected_code: str,
    fake_redis: FakeRedis,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url", json={"url": blocked_url}, headers=AUTH_HEADERS
        )

    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == expected_code
    # Must never touch cache when blocked by SSRF
    assert fake_redis.get_calls == 0
    assert fake_redis.set_calls == 0


@pytest.mark.asyncio
async def test_dns_resolving_to_private_ip_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_getaddrinfo(host: str, port: int, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.10.25", port))]

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url",
            json={"url": "https://rebind.example.com/"},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "ssrf_blocked"
    assert fake_redis.get_calls == 0


@pytest.mark.asyncio
async def test_redirect_to_local_ip_blocked_via_ssrf(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        if host == "public.example.com":
            return ["93.184.216.34"]
        raise AssertionError(f"Unexpected DNS lookup for {host}")

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/secret"})

    mock_transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        service, "_build_pinned_transport", lambda host, ips: mock_transport
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url",
            json={"url": "https://public.example.com/start"},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "ssrf_blocked"
    assert fake_redis.set_calls == 0


@pytest.mark.asyncio
async def test_pinned_dns_backend_connects_only_to_validated_ip() -> None:
    connected_targets: list[tuple[str, int]] = []

    class DummyInnerBackend(httpcore.AsyncNetworkBackend):
        async def connect_tcp(
            self,
            host,
            port,
            timeout=None,  # noqa: ASYNC109
            local_address=None,
            socket_options=None,
        ):
            connected_targets.append((host, port))
            return object()  # type: ignore[return-value]

        async def connect_unix_socket(
            self,
            path,
            timeout=None,  # noqa: ASYNC109
            socket_options=None,
        ):
            raise AssertionError("Should not reach inner unix socket")

        async def sleep(self, seconds):
            return None

    backend = _PinnedDNSBackend("example.com", ["93.184.216.34"], DummyInnerBackend())
    await backend.connect_tcp("example.com", 443)
    assert connected_targets == [("93.184.216.34", 443)]

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("127.0.0.1", 443)

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_unix_socket("/var/run/docker.sock")


# ---------------------------------------------------------------------------
# Web Extraction, 5MB Ceiling, Token Validation & Redis Cache (URL only)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_url_extraction_tokens_and_redis_cache_hit_miss(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    html = (
        "<html><head><title>Article Title</title>"
        "<meta name='author' content='Ada Lovelace'></head>"
        "<body><article><h1>Analytical Engine</h1>"
        "<p>This article explains algorithmic extraction and token counting "
        "with &lt;|endoftext|&gt; literals.</p>"
        "<p>Second paragraph provides additional structured context "
        "for extraction.</p>"
        "</article></body></html>"
    )
    fetch_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal fetch_count
        fetch_count += 1
        return httpx.Response(
            200, headers={"Content-Type": "text/html; charset=utf-8"}, text=html
        )

    mock_transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        service, "_build_pinned_transport", lambda host, ips: mock_transport
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # 1st call -> cache miss
        r1 = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/post"},
            headers=AUTH_HEADERS,
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["cached"] is False
        assert d1["final_url"] == "https://example.com/post"
        assert d1["encoding"] == "cl100k_base"
        assert "Analytical Engine" in d1["content"]
        assert d1["metadata"]["author"] == "Ada Lovelace"
        assert d1["char_count"] == len(d1["content"])

        expected_tokens = len(
            tiktoken.get_encoding("cl100k_base").encode(
                d1["content"], disallowed_special=()
            )
        )
        assert d1["token_count"] == expected_tokens
        assert d1["token_count"] > 0
        assert fetch_count == 1
        assert fake_redis.get_calls == 1
        assert fake_redis.set_calls == 1
        assert all(
            ttl == service.URL_CACHE_TTL_SECONDS for ttl in fake_redis.ttls.values()
        )

        # 2nd call -> cache hit (no origin HTTP fetch)
        r2 = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/post"},
            headers=AUTH_HEADERS,
        )
        assert r2.status_code == 200
        d2 = r2.json()
        assert d2["cached"] is True
        assert d2["content"] == d1["content"]
        assert d2["token_count"] == d1["token_count"]
        assert fetch_count == 1
        assert fake_redis.get_calls == 2
        assert fake_redis.set_calls == 1

        # Different encoding -> separate cache key, cache miss, recomputed tokens
        r3 = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/post", "encoding": "o200k_base"},
            headers=AUTH_HEADERS,
        )
        assert r3.status_code == 200
        d3 = r3.json()
        assert d3["cached"] is False
        assert d3["encoding"] == "o200k_base"
        expected_o200k = len(
            tiktoken.get_encoding("o200k_base").encode(
                d3["content"], disallowed_special=()
            )
        )
        assert d3["token_count"] == expected_o200k
        assert fetch_count == 2


@pytest.mark.asyncio
async def test_url_extraction_5mb_ceiling_via_content_length_and_stream(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    # Case 1: Content-Length header exceeds 5MB
    def oversized_cl_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Type": "text/html",
                "Content-Length": str(MAX_WEB_BYTES + 1),
            },
            content=b"<html><body><p>small</p></body></html>",
        )

    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(oversized_cl_handler),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_cl = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/big-cl"},
            headers=AUTH_HEADERS,
        )
    assert r_cl.status_code == 413
    assert r_cl.json()["error"]["code"] == "payload_too_large"
    assert fake_redis.set_calls == 0

    # Case 2: Streaming body exceeds 5MB without Content-Length
    class ChunkedStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"<html><body><article><p>"
            chunk = b"a" * (512 * 1024)
            for _ in range(11):  # 5.5 MiB total
                yield chunk
            yield b"</p></article></body></html>"

    def oversized_stream_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"Content-Type": "text/html"}, stream=ChunkedStream()
        )

    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(oversized_stream_handler),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_stream = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/big-stream"},
            headers=AUTH_HEADERS,
        )
    assert r_stream.status_code == 413
    assert r_stream.json()["error"]["code"] == "payload_too_large"
    assert fake_redis.set_calls == 0


@pytest.mark.asyncio
async def test_url_extraction_5mb_exact_boundary_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    prefix = b"<html><body><article><p>"
    suffix = b"</p></article></body></html>"
    # Build plain text padded with spaces so total is exact MAX_WEB_BYTES (5 MiB)
    filler_len = MAX_WEB_BYTES - len(prefix) - len(suffix)
    body = (
        prefix
        + b"Hello boundary content. "
        + (b" " * (filler_len - len(b"Hello boundary content. ")))
        + suffix
    )
    assert len(body) == MAX_WEB_BYTES

    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200, headers={"Content-Type": "text/html"}, content=body
            )
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/exact-5mb"},
            headers=AUTH_HEADERS,
        )
    assert resp.status_code == 200
    assert "Hello boundary content." in resp.json()["content"]


@pytest.mark.asyncio
async def test_url_extraction_resilient_when_redis_unavailable(
    monkeypatch: pytest.MonkeyPatch,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    broken_redis = AsyncMock()
    broken_redis.get.side_effect = RedisError("Redis connection refused")
    broken_redis.set.side_effect = RedisError("Redis connection refused")
    app.dependency_overrides[get_redis] = lambda: broken_redis

    html = (
        "<html><body><article><p>Resilient content works without Redis.</p>"
        "</article></body></html>"
    )
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200, headers={"Content-Type": "text/html"}, text=html
            )
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/resilient"},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 200
    assert resp.json()["cached"] is False
    assert "Resilient content works without Redis." in resp.json()["content"]


@pytest.mark.asyncio
async def test_url_error_paths_upstream_and_content_type(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Upstream 404
        monkeypatch.setattr(
            service,
            "_build_pinned_transport",
            lambda h, i: httpx.MockTransport(
                lambda req: httpx.Response(404, text="Not found")
            ),
        )
        r_404 = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/missing"},
            headers=AUTH_HEADERS,
        )
        assert r_404.status_code == 502
        assert r_404.json()["error"]["code"] == "upstream_http_error"

        # Unsupported content type (PDF via /url)
        monkeypatch.setattr(
            service,
            "_build_pinned_transport",
            lambda h, i: httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    headers={"Content-Type": "application/pdf"},
                    content=b"%PDF-1.4",
                )
            ),
        )
        r_pdf_mime = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/doc.pdf"},
            headers=AUTH_HEADERS,
        )
        assert r_pdf_mime.status_code == 415
        assert r_pdf_mime.json()["error"]["code"] == "unsupported_media_type"

        # Empty HTML page
        monkeypatch.setattr(
            service,
            "_build_pinned_transport",
            lambda h, i: httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    headers={"Content-Type": "text/html"},
                    text="<html><body></body></html>",
                )
            ),
        )
        r_empty = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/empty"},
            headers=AUTH_HEADERS,
        )
        assert r_empty.status_code == 422
        assert r_empty.json()["error"]["code"] == "extraction_empty"

        # Timeout
        def timeout_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Timed out", request=request)

        monkeypatch.setattr(
            service,
            "_build_pinned_transport",
            lambda h, i: httpx.MockTransport(timeout_handler),
        )
        r_timeout = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/slow"},
            headers=AUTH_HEADERS,
        )
        assert r_timeout.status_code == 504
        assert r_timeout.json()["error"]["code"] == "upstream_timeout"

        # Blank URL validation error
        r_blank = await client.post(
            "/v1/extract/url", json={"url": "   "}, headers=AUTH_HEADERS
        )
        assert r_blank.status_code == 422
        assert r_blank.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_url_too_many_redirects(
    monkeypatch: pytest.MonkeyPatch, fake_redis: FakeRedis
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                302, headers={"Location": "https://example.com/loop"}
            )
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/loop"},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "too_many_redirects"


# ---------------------------------------------------------------------------
# PDF Extraction: Page Limits, 10MB Ceiling, Token Validation, No Redis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pdf_extraction_success_tokens_and_no_redis_usage():
    # Override get_redis to fail loudly if /pdf ever touches Redis
    redis_spy = AsyncMock()
    app.dependency_overrides[get_redis] = lambda: redis_spy

    pdf_bytes = _make_pdf_bytes(
        pages=3,
        text_per_page="Markdown paragraph with <|endoftext|> marker",
        title="Architecture Spec",
        author="Backend Lead",
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("../../specs/arch.pdf", pdf_bytes, "application/pdf")},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["filename"] == "arch.pdf"
    assert data["output_format"] == "markdown"
    assert data["page_count"] == 3
    assert data["size_bytes"] == len(pdf_bytes)
    assert data["encoding"] == "cl100k_base"
    assert "Structured" not in data["content"]  # uses custom text_per_page
    assert "Markdown paragraph" in data["content"]
    assert data["char_count"] == len(data["content"])
    assert data["metadata"]["title"] == "Architecture Spec"
    assert data["metadata"]["author"] == "Backend Lead"

    expected_tokens = len(
        tiktoken.get_encoding("cl100k_base").encode(
            data["content"], disallowed_special=()
        )
    )
    assert data["token_count"] == expected_tokens
    assert data["token_count"] > 0

    # Exclusively for URL extractions: PDF must never read/write Redis
    redis_spy.get.assert_not_called()
    redis_spy.set.assert_not_called()


@pytest.mark.asyncio
async def test_pdf_extraction_custom_encoding_and_blank_page_zero_tokens():
    pdf_bytes = _make_pdf_bytes(
        pages=2, text_per_page="Token benchmark text for o200k_base."
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("doc.pdf", pdf_bytes, "application/pdf")},
            data={"encoding": "o200k_base"},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["encoding"] == "o200k_base"
    expected_tokens = len(
        tiktoken.get_encoding("o200k_base").encode(
            data["content"], disallowed_special=()
        )
    )
    assert data["token_count"] == expected_tokens

    # Blank 1-page PDF yields 0 tokens
    blank_pdf = _make_pdf_bytes(pages=1, blank=True)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        blank_resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("blank.pdf", blank_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )
    assert blank_resp.status_code == 200
    assert blank_resp.json()["token_count"] == 0
    assert blank_resp.json()["char_count"] == 0
    assert blank_resp.json()["page_count"] == 1


@pytest.mark.asyncio
async def test_pdf_exceeding_50_page_limit_is_rejected():
    over_limit_pdf = _make_pdf_bytes(pages=MAX_PDF_PAGES + 1, text_per_page="Overflow")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("too_many_pages.pdf", over_limit_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "page_limit_exceeded"
    assert err["details"]["page_count"] == MAX_PDF_PAGES + 1
    assert err["details"]["max_pages"] == MAX_PDF_PAGES


@pytest.mark.asyncio
async def test_pdf_exact_50_pages_boundary_succeeds():
    exact_limit_pdf = _make_pdf_bytes(
        pages=MAX_PDF_PAGES, text_per_page="Boundary page"
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("fifty_pages.pdf", exact_limit_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["page_count"] == MAX_PDF_PAGES
    assert data["token_count"] > 0


@pytest.mark.asyncio
async def test_pdf_exceeding_10mb_limit_is_rejected():
    oversized = b"%PDF-1.4\n" + (b"0" * (MAX_PDF_BYTES - len(b"%PDF-1.4\n") + 1))
    assert len(oversized) == MAX_PDF_BYTES + 1

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("huge.pdf", oversized, "application/pdf")},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "payload_too_large"


@pytest.mark.asyncio
async def test_pdf_empty_corrupt_nonpdf_and_encrypted_errors():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Empty file
        r_empty = await client.post(
            "/v1/extract/pdf",
            files={"file": ("empty.pdf", b"", "application/pdf")},
            headers=AUTH_HEADERS,
        )
        assert r_empty.status_code == 400
        assert r_empty.json()["error"]["code"] == "empty_file"

        # Non-PDF bytes
        r_not_pdf = await client.post(
            "/v1/extract/pdf",
            files={"file": ("fake.pdf", b"NOT A PDF FILE", "application/pdf")},
            headers=AUTH_HEADERS,
        )
        assert r_not_pdf.status_code == 400
        assert r_not_pdf.json()["error"]["code"] == "invalid_pdf"

        # Corrupted PDF with valid magic prefix
        r_corrupt = await client.post(
            "/v1/extract/pdf",
            files={
                "file": (
                    "corrupt.pdf",
                    b"%PDF-1.4\ncorrupted-body-data",
                    "application/pdf",
                )
            },
            headers=AUTH_HEADERS,
        )
        assert r_corrupt.status_code == 400
        assert r_corrupt.json()["error"]["code"] == "invalid_pdf"

        # Password-protected PDF
        encrypted_pdf = _make_pdf_bytes(pages=1, password="secret")
        r_enc = await client.post(
            "/v1/extract/pdf",
            files={"file": ("locked.pdf", encrypted_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )
        assert r_enc.status_code == 422
        assert r_enc.json()["error"]["code"] == "encrypted_pdf"

        # Invalid encoding form field
        valid_pdf = _make_pdf_bytes(pages=1)
        r_bad_enc = await client.post(
            "/v1/extract/pdf",
            files={"file": ("valid.pdf", valid_pdf, "application/pdf")},
            data={"encoding": "invalid_tokenizer"},
            headers=AUTH_HEADERS,
        )
        assert r_bad_enc.status_code == 422
        assert r_bad_enc.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_url_use_cache_false_relative_redirect_and_plain_text(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    hits = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal hits
        hits += 1
        if request.url.path == "/old":
            return httpx.Response(301, headers={"Location": "/new"})
        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            text="Plain text document body.",
        )

    monkeypatch.setattr(
        service, "_build_pinned_transport", lambda h, i: httpx.MockTransport(handler)
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r1 = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/old"},
            headers=AUTH_HEADERS,
        )
        assert r1.status_code == 200
        d1 = r1.json()
        assert d1["final_url"] == "https://example.com/new"
        assert d1["content"] == "Plain text document body."
        assert d1["cached"] is False
        assert d1["token_count"] == len(
            tiktoken.get_encoding("cl100k_base").encode(
                "Plain text document body.", disallowed_special=()
            )
        )
        assert hits == 2  # /old + /new

        # Bypass cache read with use_cache=False
        r2 = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/old", "use_cache": False},
            headers=AUTH_HEADERS,
        )
        assert r2.status_code == 200
        assert r2.json()["cached"] is False
        assert hits == 4  # /old + /new fetched again


@pytest.mark.asyncio
async def test_build_pinned_transport_uses_pinned_ip_over_real_tcp() -> None:
    received_headers: bytes = b""

    async def handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal received_headers
        received_headers = await reader.readuntil(b"\r\n\r\n")
        body = (
            b"<html><body><article><p>Pinned TCP payload works cleanly.</p>"
            b"</article></body></html>"
        )
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        transport = service._build_pinned_transport(
            "nonexistent.invalid", ["127.0.0.1"]
        )
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            resp = await client.get(f"http://nonexistent.invalid:{port}/article")
        assert resp.status_code == 200
        assert "Pinned TCP payload works cleanly." in resp.text
        assert f"host: nonexistent.invalid:{port}".encode() in received_headers.lower()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_pdf_filename_dot_sanitization():
    assert service._sanitize_filename("..") == "document.pdf"
    assert service._sanitize_filename(".") == "document.pdf"
    assert service._sanitize_filename("") == "document.pdf"
    assert service._sanitize_filename(r"C:\tmp\..\report.pdf") == "report.pdf"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("malformed_url", "expected_code"),
    [
        ("http://example.com:99999/", "invalid_url"),
        ("http://example.com:abc/", "invalid_url"),
        ("http://[/", "invalid_url"),
        ("http://]bad[/", "invalid_url"),
        ("http://@93.184.216.34/", "invalid_url"),
        ("http://:@93.184.216.34/", "invalid_url"),
        ("https://example.com\n/", "invalid_url"),
        ("https://example.com\x00/", "invalid_url"),
        ("http://93.184.216.34:0/", "ssrf_blocked"),
    ],
)
async def test_malformed_urls_and_ssrf_bypass_edge_cases(
    malformed_url: str,
    expected_code: str,
    fake_redis: FakeRedis,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url", json={"url": malformed_url}, headers=AUTH_HEADERS
        )

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == expected_code
    assert fake_redis.get_calls == 0
    assert fake_redis.set_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("redirect_location", "expected_code"),
    [
        ("http://example.com:99999/", "invalid_url"),
        ("//127.0.0.1/secret", "ssrf_blocked"),
        ("http://@93.184.216.34/", "invalid_url"),
        ("http://93.184.216.34:0/", "ssrf_blocked"),
    ],
)
async def test_redirect_to_malformed_or_bypass_url_rejected(
    redirect_location: str,
    expected_code: str,
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(302, headers={"Location": redirect_location})
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/start"},
            headers=AUTH_HEADERS,
        )

    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == expected_code
    assert fake_redis.set_calls == 0


@pytest.fixture
def ephemeral_tls_cert(tmp_path: Path) -> tuple[Path, Path]:
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        pytest.skip("openssl CLI not available to generate ephemeral test certificate")

    cert_path = tmp_path / "server.crt"
    key_path = tmp_path / "server.key"
    subprocess.run(
        [
            openssl_bin,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=pinned.example.test",
            "-addext",
            "subjectAltName=DNS:pinned.example.test",
        ],
        check=True,
        capture_output=True,
    )
    return cert_path, key_path


@pytest.mark.asyncio
async def test_pinned_dns_backend_tls_sni_and_cert_verification(
    ephemeral_tls_cert: tuple[Path, Path],
):
    cert_path, key_path = ephemeral_tls_cert

    sni_seen: list[str | None] = []
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(str(cert_path), str(key_path))
    srv_ctx.sni_callback = lambda _sock, name, _ctx: sni_seen.append(name)

    async def handle_tls(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.readuntil(b"\r\n\r\n")
        body = (
            b"<html><body><article><p>TLS SNI certificate pinning works.</p>"
            b"</article></body></html>"
        )
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle_tls, "127.0.0.1", 0, ssl=srv_ctx)
    port = server.sockets[0].getsockname()[1]

    cli_ctx = ssl.create_default_context(cafile=str(cert_path))
    transport = httpx.AsyncHTTPTransport(verify=cli_ctx, trust_env=False)
    transport._pool._network_backend = _PinnedDNSBackend(
        expected_host="pinned.example.test",
        allowed_ips=["127.0.0.1"],
        inner=transport._pool._network_backend,
    )

    try:
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            resp = await client.get(f"https://pinned.example.test:{port}/secure")
        assert resp.status_code == 200
        assert "TLS SNI certificate pinning works." in resp.text
        assert sni_seen == ["pinned.example.test"]
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_url_gzip_bomb_bounded_memory_and_compressed_boundary():
    # 30 MiB payload compressed to ~30 KiB: must abort at 5 MiB with bounded RAM
    gz_bomb = gzip.compress(b"A" * (30 * 1024 * 1024))
    prefix = b"<html><body><article><p>Exact compressed boundary. "
    suffix = b"</p></article></body></html>"
    exact_raw = prefix + (b" " * (MAX_WEB_BYTES - len(prefix) - len(suffix))) + suffix
    assert len(exact_raw) == MAX_WEB_BYTES
    exact_gz = gzip.compress(exact_raw)
    over_gz = gzip.compress(exact_raw + b"x")

    async def handle_http(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        req_head = await reader.readuntil(b"\r\n\r\n")
        if b"/exact" in req_head:
            payload = exact_gz
        elif b"/over" in req_head:
            payload = over_gz
        else:
            payload = gz_bomb
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Encoding: gzip\r\n"
            + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle_http, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        tracemalloc.start()
        try:
            t_bomb = service._build_pinned_transport("bomb.example", ["127.0.0.1"])
            with pytest.raises(service.AppError) as exc_info:
                await service._fetch_url_bytes(
                    f"http://bomb.example:{port}/bomb", ["127.0.0.1"], transport=t_bomb
                )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert exc_info.value.status_code == 413
        assert exc_info.value.code == "payload_too_large"
        assert (
            peak < 9 * 1024 * 1024
        )  # Strictly bounded well below 30 MiB decompressed bomb

        t_exact = service._build_pinned_transport("bomb.example", ["127.0.0.1"])
        _, got_exact, _, _ = await service._fetch_url_bytes(
            f"http://bomb.example:{port}/exact", ["127.0.0.1"], transport=t_exact
        )
        assert len(got_exact) == MAX_WEB_BYTES

        t_over = service._build_pinned_transport("bomb.example", ["127.0.0.1"])
        with pytest.raises(service.AppError) as over_exc:
            await service._fetch_url_bytes(
                f"http://bomb.example:{port}/over", ["127.0.0.1"], transport=t_over
            )
        assert over_exc.value.status_code == 413
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_url_deflate_and_corrupt_or_unsupported_encoding():
    raw_html = (
        b"<html><body><article><p>Deflate decompression verified.</p>"
        b"</article></body></html>"
    )
    zlib_body = zlib.compress(raw_html)
    comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_deflate_body = comp.compress(raw_html) + comp.flush()

    class RawStream(httpx.AsyncByteStream):
        def __init__(self, data: bytes) -> None:
            self._data = data

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield self._data

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/zlib":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Encoding": "deflate"},
                stream=RawStream(zlib_body),
            )
        if request.url.path == "/raw":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Encoding": "deflate"},
                stream=RawStream(raw_deflate_body),
            )
        if request.url.path == "/corrupt":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
                stream=RawStream(b"not-gzip"),
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Encoding": "br"},
            stream=RawStream(b"brotli"),
        )

    transport = httpx.MockTransport(handler)
    for ok_path in ("/zlib", "/raw"):
        _, got, _, _ = await service._fetch_url_bytes(
            f"https://example.com{ok_path}", ["93.184.216.34"], transport=transport
        )
        assert got == raw_html

    for bad_path in ("/corrupt", "/br"):
        with pytest.raises(service.AppError) as exc_info:
            await service._fetch_url_bytes(
                f"https://example.com{bad_path}", ["93.184.216.34"], transport=transport
            )
        assert exc_info.value.status_code == 502
        assert exc_info.value.code == "upstream_error"


@pytest.mark.asyncio
async def test_fetch_url_bytes_preserves_caller_transport_across_redirects(
    monkeypatch: pytest.MonkeyPatch,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    class StatefulTransport(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.closed = False

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if self.closed:
                raise RuntimeError("Transport was closed prematurely on redirect!")
            if request.url.path == "/hop1":
                return httpx.Response(
                    302, headers={"Location": "https://example.com/hop2"}
                )
            return httpx.Response(
                200, headers={"Content-Type": "text/plain"}, text="Redirected cleanly."
            )

        async def aclose(self) -> None:
            self.closed = True

    transport = StatefulTransport()
    final_url, raw, _, _ = await service._fetch_url_bytes(
        "https://example.com/hop1", ["93.184.216.34"], transport=transport
    )
    assert final_url == "https://example.com/hop2"
    assert raw == b"Redirected cleanly."
    assert transport.closed is False


@pytest.mark.asyncio
async def test_url_extraction_degrades_when_redis_times_out(
    monkeypatch: pytest.MonkeyPatch,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)
    monkeypatch.setattr(service, "REDIS_OP_TIMEOUT_SECONDS", 0.05)

    class SlowRedis:
        async def get(self, key: str) -> str | None:
            await asyncio.sleep(1.0)
            return None

        async def set(self, key: str, value: str, ex: int | None = None) -> bool:
            await asyncio.sleep(1.0)
            return True

    app.dependency_overrides[get_redis] = lambda: SlowRedis()
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    "<html><body><article>"
                    "<p>Returned fast despite hung Redis.</p>"
                    "</article></body></html>"
                ),
            )
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await asyncio.wait_for(
            client.post(
                "/v1/extract/url",
                json={"url": "https://example.com/slow-redis"},
                headers=AUTH_HEADERS,
            ),
            timeout=1.0,
        )
    assert resp.status_code == 200
    assert resp.json()["cached"] is False
    assert "Returned fast despite hung Redis." in resp.json()["content"]


def _dir_entries(path: Path) -> list[Path]:
    return list(path.iterdir())


@pytest.mark.asyncio
async def test_pdf_exact_10mb_boundary_zero_pages_streaming_limit_and_post_open_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    # 1. Exact 10 MiB valid PDF padded with PDF comment succeeds
    base_pdf = _make_pdf_bytes(pages=1, text_per_page="Exact 10 MiB boundary test.")
    pad_len = MAX_PDF_BYTES - len(base_pdf)
    assert pad_len > 2
    exact_10mb_pdf = base_pdf + b"\n%" + (b"0" * (pad_len - 2))
    assert len(exact_10mb_pdf) == MAX_PDF_BYTES

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_exact = await client.post(
            "/v1/extract/pdf",
            files={"file": ("exact_10mb.pdf", exact_10mb_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )
    assert r_exact.status_code == 200
    assert r_exact.json()["size_bytes"] == MAX_PDF_BYTES
    assert r_exact.json()["token_count"] > 0

    # 2. Streaming chunk check when UploadFile.size is None and bytes > 10 MiB
    oversized_stream = UploadFile(
        file=io.BytesIO(b"%PDF-1.4\n" + (b"0" * MAX_PDF_BYTES)),
        filename="stream_huge.pdf",
        size=None,
    )
    with pytest.raises(service.AppError) as stream_exc:
        await service.extract_pdf(
            oversized_stream,
            service.PdfExtractOptions(encoding="cl100k_base"),
        )
    assert stream_exc.value.status_code == 413
    assert stream_exc.value.code == "payload_too_large"

    # 3. 0-page valid-structure PDF rejected with 400 invalid_pdf
    zero_page_pdf = (
        b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Count 0 /Kids [] >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\nstartxref\n110\n%%EOF\n"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_zero = await client.post(
            "/v1/extract/pdf",
            files={"file": ("zero.pdf", zero_page_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )
    assert r_zero.status_code == 400
    assert r_zero.json()["error"]["code"] == "invalid_pdf"

    # 4. Embedded image PDF writes zero files to cwd
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Document with embedded image.")
    pix = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 12, 12), 0)
    pix.clear_with(128)
    page.insert_image(pymupdf.Rect(72, 120, 140, 188), pixmap=pix)
    img_pdf = doc.tobytes()
    doc.close()

    monkeypatch.chdir(tmp_path)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_img = await client.post(
            "/v1/extract/pdf",
            files={"file": ("img.pdf", img_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )
    assert r_img.status_code == 200
    assert await asyncio.to_thread(_dir_entries, tmp_path) == []

    # 5. Post-open pymupdf4llm failure returns clean 422 extraction_failed
    def broken_to_markdown(*args, **kwargs):
        raise RuntimeError("Corrupt page stream")

    monkeypatch.setattr(pymupdf4llm, "to_markdown", broken_to_markdown)
    valid_pdf = _make_pdf_bytes(pages=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_err = await client.post(
            "/v1/extract/pdf",
            files={"file": ("broken_stream.pdf", valid_pdf, "application/pdf")},
            headers=AUTH_HEADERS,
        )
    assert r_err.status_code == 422
    assert r_err.json()["error"]["code"] == "extraction_failed"


@pytest.mark.asyncio
async def test_web_extraction_options_lxml_error_and_surrogate_sanitization(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    html = (
        "<html><body><article><h1>Heading</h1>"
        "<p>Body with <a href='https://example.org/ref'>reference link</a> inside.</p>"
        "</article></body></html>"
    )
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200, headers={"Content-Type": "text/html"}, text=html
            )
        ),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_txt = await client.post(
            "/v1/extract/url",
            json={
                "url": "https://example.com/opts",
                "output_format": "txt",
                "include_links": True,
            },
            headers=AUTH_HEADERS,
        )
    assert r_txt.status_code == 200
    assert r_txt.json()["output_format"] == "txt"
    assert "Body with" in r_txt.json()["content"]

    # lxml.etree.Error inside trafilatura.extract produces clean 422 extraction_failed
    def raise_lxml(*args, **kwargs):
        raise lxml.etree.XMLSyntaxError("Bad tree", 1, 1, 1)

    monkeypatch.setattr(service.trafilatura, "extract", raise_lxml)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_lxml = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/bad-tree", "use_cache": False},
            headers=AUTH_HEADERS,
        )
    assert r_lxml.status_code == 422
    assert r_lxml.json()["error"]["code"] == "extraction_failed"

    # Unpaired UTF-16 surrogates are sanitized before UTF-8 JSON serialization
    sanitized = service._sanitize_text("clean\ud800text")
    sanitized.encode("utf-8")


@pytest.mark.asyncio
async def test_concurrent_pdf_and_url_extractions(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    "<html><body><article>"
                    f"<p>Concurrent URL item {req.url.path} payload.</p>"
                    "</article></body></html>"
                ),
            )
        ),
    )

    pdfs = [
        _make_pdf_bytes(pages=2, text_per_page=f"Concurrent PDF doc {idx}")
        for idx in range(5)
    ]

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        url_tasks = [
            client.post(
                "/v1/extract/url",
                json={"url": f"https://example.com/item/{idx}"},
                headers=AUTH_HEADERS,
            )
            for idx in range(5)
        ]
        pdf_tasks = [
            client.post(
                "/v1/extract/pdf",
                files={"file": (f"doc_{idx}.pdf", pdf_bytes, "application/pdf")},
                headers=AUTH_HEADERS,
            )
            for idx, pdf_bytes in enumerate(pdfs)
        ]
        results = await asyncio.gather(*url_tasks, *pdf_tasks)

    for resp in results:
        assert resp.status_code == 200
        data = resp.json()
        assert data["token_count"] > 0
        assert data["char_count"] == len(data["content"])


@pytest.mark.asyncio
async def test_pdf_missing_file_rejected_and_default_options():
    opts = service.PdfExtractOptions()
    assert opts.encoding == "cl100k_base"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            data={"encoding": "cl100k_base"},
            headers=AUTH_HEADERS,
        )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


@pytest.mark.asyncio
async def test_chunked_raw_deflate_one_byte_initial_chunk_and_bomb():
    raw_html = (
        b"<html><body><article><p>Split-chunk raw deflate works cleanly."
        b"</p></article></body></html>"
    )
    comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_deflate = comp.compress(raw_html) + comp.flush()

    class OneByteFirstStream(httpx.AsyncByteStream):
        def __init__(self, data: bytes) -> None:
            self._data = data

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield self._data[:1]
            yield self._data[1:]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/bomb":
            bomb_comp = zlib.compressobj(wbits=-zlib.MAX_WBITS)
            bomb = bomb_comp.compress(b"Z" * (MAX_WEB_BYTES + 2048)) + bomb_comp.flush()
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Encoding": "deflate"},
                stream=OneByteFirstStream(bomb),
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Encoding": "deflate"},
            stream=OneByteFirstStream(raw_deflate),
        )

    transport = httpx.MockTransport(handler)
    _, decoded, _, _ = await service._fetch_url_bytes(
        "https://example.com/raw-split", ["93.184.216.34"], transport=transport
    )
    assert decoded == raw_html

    with pytest.raises(service.AppError) as bomb_exc:
        await service._fetch_url_bytes(
            "https://example.com/bomb", ["93.184.216.34"], transport=transport
        )
    assert bomb_exc.value.status_code == 413
    assert bomb_exc.value.code == "payload_too_large"


@pytest.mark.asyncio
async def test_multi_member_gzip_decoded_and_bounded():
    part1 = b"<html><body><article><p>First gzip member. </p>"
    part2 = b"<p>Second gzip member.</p></article></body></html>"
    multi_gz = gzip.compress(part1) + gzip.compress(part2)

    class SplitStream(httpx.AsyncByteStream):
        def __init__(self, chunks: list[bytes]) -> None:
            self._chunks = chunks

        async def __aiter__(self) -> AsyncIterator[bytes]:
            for chunk in self._chunks:
                yield chunk

    m1_exact = gzip.compress(b"A" * MAX_WEB_BYTES)
    m2_overflow = gzip.compress(b"B")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/boundary":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
                stream=SplitStream([m1_exact, m2_overflow]),
            )
        mid = len(gzip.compress(part1))
        return httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
            stream=SplitStream([multi_gz[: mid - 2], multi_gz[mid - 2 :]]),
        )

    transport = httpx.MockTransport(handler)
    _, decoded, _, _ = await service._fetch_url_bytes(
        "https://example.com/multi", ["93.184.216.34"], transport=transport
    )
    assert decoded == part1 + part2

    with pytest.raises(service.AppError) as exc_info:
        await service._fetch_url_bytes(
            "https://example.com/boundary", ["93.184.216.34"], transport=transport
        )
    assert exc_info.value.status_code == 413
    assert exc_info.value.code == "payload_too_large"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "transition_url",
    [
        "http://[64:ff9b::127.0.0.1]/latest/meta-data/",
        "http://[::ffff:0:127.0.0.1]/admin",
        "http://[fec0::1]/internal",
    ],
)
async def test_ssrf_blocks_ipv6_transition_and_sitelocal_addresses(
    transition_url: str,
    fake_redis: FakeRedis,
):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/url", json={"url": transition_url}, headers=AUTH_HEADERS
        )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "ssrf_blocked"
    assert fake_redis.get_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "encoding_name",
    ["cl100k_base", "o200k_base", "p50k_base", "r50k_base"],
)
async def test_all_supported_tiktoken_encodings_verified(encoding_name: str):
    pdf_bytes = _make_pdf_bytes(
        pages=1, text_per_page="Token encoding consistency check across tokenizers."
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/v1/extract/pdf",
            files={"file": ("enc.pdf", pdf_bytes, "application/pdf")},
            data={"encoding": encoding_name},
            headers=AUTH_HEADERS,
        )
    assert resp.status_code == 200
    data = resp.json()
    expected = len(
        tiktoken.get_encoding(encoding_name).encode(
            data["content"], disallowed_special=()
        )
    )
    assert data["token_count"] == expected
    assert data["token_count"] > 0


@pytest.mark.asyncio
async def test_bom_stripping_filename_control_chars_and_overall_timeout(
    monkeypatch: pytest.MonkeyPatch,
    fake_redis: FakeRedis,
):
    assert service._sanitize_filename("report\x00\r\n.pdf") == "report.pdf"

    async def fake_resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr("app.core.ssrf.resolve_public_ips", fake_resolve)

    # UTF-8 BOM stripped cleanly from plain text
    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                headers={"Content-Type": "text/plain; charset=utf-8"},
                content=b"\xef\xbb\xbfBOM-free text.",
            )
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_bom = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/bom.txt"},
            headers=AUTH_HEADERS,
        )
    assert r_bom.status_code == 200
    assert r_bom.json()["content"] == "BOM-free text."

    # Slowloris total fetch timeout returns 504 upstream_timeout
    monkeypatch.setattr(service, "TOTAL_FETCH_TIMEOUT_SECONDS", 0.05)

    class DripStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"<html><body><p>"
            await asyncio.sleep(0.5)
            yield b"too late</p></body></html>"

    monkeypatch.setattr(
        service,
        "_build_pinned_transport",
        lambda h, i: httpx.MockTransport(
            lambda req: httpx.Response(
                200, headers={"Content-Type": "text/html"}, stream=DripStream()
            )
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        r_slow = await client.post(
            "/v1/extract/url",
            json={"url": "https://example.com/slowloris"},
            headers=AUTH_HEADERS,
        )
    assert r_slow.status_code == 504
    assert r_slow.json()["error"]["code"] == "upstream_timeout"
