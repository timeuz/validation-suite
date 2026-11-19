from datetime import datetime, timedelta, timezone
import ipaddress
from pathlib import Path
import socket
import ssl
import sys
from unittest.mock import AsyncMock, MagicMock, patch

_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
import httpx
from pydantic import ValidationError
import pytest

from app.core.config import get_settings
from app.core.exceptions import AppError
from app.main import app
from app.modules.sec_audit.router import get_audit_service
from app.modules.sec_audit.schemas import (
    AuditRequest,
    SSLInfo,
    ThreatIntelResult,
)
from app.modules.sec_audit.service import (
    OPENPHISH_FEED_URL,
    REDIS_KEY_FEEDS_LAST_SYNC,
    REDIS_KEY_OPENPHISH_HOSTS,
    REDIS_KEY_OPENPHISH_URLS,
    REDIS_KEY_URLHAUS_HOSTS,
    REDIS_KEY_URLHAUS_URLS,
    URLHAUS_FEED_URL,
    SecurityAuditService,
    audit_security_headers,
    calculate_security_score,
    normalize_url_indicator,
    parse_and_validate_x509_cert,
    parse_feed_entries,
    perform_tls_handshake,
    score_to_grade,
)

PROXY_SECRET = "test-rapidapi-proxy-secret"
AUTH_HEADERS = {"X-RapidAPI-Proxy-Secret": PROXY_SECRET}

STRONG_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class FakeAsyncRedis:
    """In-memory async Redis double supporting sets, keys, and TTLs."""

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}
        self.kv: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def delete(self, key: str) -> int:
        removed = int(key in self.sets or key in self.kv)
        self.sets.pop(key, None)
        self.kv.pop(key, None)
        return removed

    async def sadd(self, key: str, *members: str) -> int:
        bucket = self.sets.setdefault(key, set())
        before = len(bucket)
        bucket.update(str(m) for m in members)
        return len(bucket) - before

    async def sismember(self, key: str, member: str) -> int:
        return int(member in self.sets.get(key, set()))

    async def expire(self, key: str, seconds: int) -> bool:
        self.ttls[key] = seconds
        return True

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.kv[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def get(self, key: str) -> str | None:
        return self.kv.get(key)

    async def rename(self, src: str, dst: str) -> bool:
        if src in self.sets:
            self.sets[dst] = self.sets.pop(src)
        if src in self.kv:
            self.kv[dst] = self.kv.pop(src)
        if src in self.ttls:
            self.ttls[dst] = self.ttls.pop(src)
        return True


def build_test_certificate(
    subject_cn: str = "example.com",
    issuer_cn: str | None = "Trusted Test Root CA",
    san_dns: list[str] | None = None,
    san_ips: list[str] | None = None,
    not_before_offset: timedelta = timedelta(days=-10),
    not_after_offset: timedelta = timedelta(days=90),
    key_size: int = 2048,
    hash_alg: hashes.HashAlgorithm = hashes.SHA256(),
    as_pem: bool = False,
) -> bytes:
    """Generates a real X.509 certificate in DER or PEM format for testing."""
    subject_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])

    if issuer_cn is None or issuer_cn == subject_cn:
        # Self-signed certificate
        issuer_name = subject_name
        signing_key = subject_key
    else:
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + not_before_offset)
        .not_valid_after(now + not_after_offset)
    )

    general_names: list[x509.GeneralName] = []
    if san_dns is None:
        general_names.append(x509.DNSName(subject_cn))
    else:
        general_names.extend(x509.DNSName(d) for d in san_dns)
    if san_ips:
        general_names.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips)

    if general_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )

    cert = builder.sign(private_key=signing_key, algorithm=hash_alg)
    encoding = serialization.Encoding.PEM if as_pem else serialization.Encoding.DER
    return cert.public_bytes(encoding)


@pytest.fixture(autouse=True)
def _configure_proxy_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RAPIDAPI_PROXY_SECRET", PROXY_SECRET)
    get_settings.cache_clear()
    yield
    app.dependency_overrides.clear()
    get_settings.cache_clear()


# =====================================================================
# 1. Pydantic v2 Strict Schema Validation Tests
# =====================================================================


def test_audit_request_valid_and_strips_whitespace():
    req = AuditRequest(url="  https://example.com/path?a=1  ")
    assert req.url == "https://example.com/path?a=1"
    assert req.timeout == 10.0
    assert req.follow_redirects is True
    assert req.sync_feeds is False


@pytest.mark.parametrize(
    "bad_payload",
    [
        {"url": ""},
        {"url": "   "},
        {"url": "not-a-valid-url"},
        {"url": "https://"},
        {"url": "https://example.com/bad path"},
        {"url": "https://example.com/\r\nX-Injected: 1"},
        {"url": 12345},
        {"url": "https://example.com", "follow_redirects": "yes"},
        {"url": "https://example.com", "timeout": 0.2},
        {"url": "https://example.com", "timeout": 99.0},
        {"url": "https://example.com", "unexpected_field": True},
        {"url": "https://example.com:99999/path"},
        {"url": "https://example.com:notaport/path"},
        {"url": "https://[::1/unclosed"},
    ],
)
def test_audit_request_strict_validation_rejects_invalid_inputs(bad_payload: dict):
    with pytest.raises(ValidationError):
        AuditRequest(**bad_payload)


# =====================================================================
# 2. X.509 Certificate & TLS/SSL Handshake Tests
# =====================================================================


def test_x509_valid_certificate_and_wildcard_matching():
    der = build_test_certificate(
        subject_cn="example.com",
        issuer_cn="DigiCert Global Root G2",
        san_dns=["example.com", "*.example.com"],
        not_before_offset=timedelta(days=-5),
        not_after_offset=timedelta(days=60),
    )

    info_exact = parse_and_validate_x509_cert(
        der,
        hostname="example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info_exact.enabled is True
    assert info_exact.valid is True
    assert info_exact.expired is False
    assert info_exact.not_yet_valid is False
    assert info_exact.self_signed is False
    assert info_exact.trusted_chain is True
    assert info_exact.hostname_match is True
    assert info_exact.key_algorithm == "RSA"
    assert info_exact.key_size == 2048
    assert info_exact.signature_algorithm == "sha256"
    assert info_exact.errors == []
    assert info_exact.warnings == []

    info_wildcard = parse_and_validate_x509_cert(
        der,
        hostname="api.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info_wildcard.valid is True
    assert info_wildcard.hostname_match is True

    # Multi-level subdomain should NOT match single-level wildcard *.example.com
    info_multilevel = parse_and_validate_x509_cert(
        der,
        hostname="deep.api.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info_multilevel.valid is False
    assert info_multilevel.hostname_match is False


def test_x509_expired_certificate_is_flagged_invalid():
    der = build_test_certificate(
        subject_cn="expired.example.com",
        issuer_cn="Test Root CA",
        not_before_offset=timedelta(days=-90),
        not_after_offset=timedelta(days=-2),
    )
    info = parse_and_validate_x509_cert(
        der,
        hostname="expired.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info.valid is False
    assert info.expired is True
    assert info.days_remaining is not None and info.days_remaining < 0
    assert any("expired" in err.lower() for err in info.errors)


def test_x509_not_yet_valid_certificate_is_flagged_invalid():
    der = build_test_certificate(
        subject_cn="future.example.com",
        issuer_cn="Test Root CA",
        not_before_offset=timedelta(days=5),
        not_after_offset=timedelta(days=95),
    )
    info = parse_and_validate_x509_cert(
        der,
        hostname="future.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info.valid is False
    assert info.not_yet_valid is True
    assert any("not started" in err.lower() for err in info.errors)


def test_x509_self_signed_and_hostname_mismatch():
    pem = build_test_certificate(
        subject_cn="internal.corp",
        issuer_cn="internal.corp",
        san_dns=["internal.corp"],
        as_pem=True,
    )
    info = parse_and_validate_x509_cert(
        pem,
        hostname="wrong.example.com",
        protocol="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
        chain_trusted=False,
        verification_error="self-signed certificate",
    )
    assert info.valid is False
    assert info.self_signed is True
    assert info.trusted_chain is False
    assert info.hostname_match is False
    assert any("self-signed" in err.lower() for err in info.errors)
    assert any("does not match" in err.lower() for err in info.errors)


def test_x509_deprecated_protocol_and_expiring_soon_warning():
    der = build_test_certificate(
        subject_cn="legacy.example.com",
        issuer_cn="Test Root CA",
        not_before_offset=timedelta(days=-30),
        not_after_offset=timedelta(days=10),
    )
    info_soon = parse_and_validate_x509_cert(
        der,
        hostname="legacy.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info_soon.valid is True
    assert any("critically soon" in w.lower() for w in info_soon.warnings)

    info_old_tls = parse_and_validate_x509_cert(
        der,
        hostname="legacy.example.com",
        protocol="TLSv1.0",
        cipher="AES128-SHA",
        chain_trusted=True,
    )
    assert info_old_tls.valid is False
    assert any("deprecated tls protocol" in e.lower() for e in info_old_tls.errors)


@pytest.mark.asyncio
async def test_perform_tls_handshake_fallback_inspects_expired_cert_on_verify_error():
    expired_der = build_test_certificate(
        subject_cn="expired.badssl.com",
        issuer_cn="Test Root CA",
        san_dns=["expired.badssl.com"],
        not_before_offset=timedelta(days=-40),
        not_after_offset=timedelta(days=-5),
    )

    mock_ssl_obj = MagicMock()
    mock_ssl_obj.getpeercert.return_value = expired_der
    mock_ssl_obj.version.return_value = "TLSv1.2"
    mock_ssl_obj.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)

    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = mock_ssl_obj
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    call_count = 0

    async def fake_open_connection(host, port, ssl, server_hostname):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            err = globals()["ssl"].SSLCertVerificationError(1, "certificate has expired")
            err.verify_message = "certificate has expired"
            raise err
        return MagicMock(), mock_writer

    with patch("app.modules.sec_audit.service.asyncio.open_connection", side_effect=fake_open_connection):
        ssl_info = await perform_tls_handshake("expired.badssl.com", "93.184.216.34", 443, timeout=3.0)

    assert call_count == 2
    assert ssl_info.enabled is True
    assert ssl_info.valid is False
    assert ssl_info.expired is True
    assert ssl_info.trusted_chain is False
    assert ssl_info.protocol == "TLSv1.2"
    assert any("expired" in err.lower() for err in ssl_info.errors)


# =====================================================================
# 3. SSRF Blocking Tests (IP literals, Ports, Credentials, DNS, Redirects)
# =====================================================================


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("blocked_url", "expected_code"),
    [
        ("http://127.0.0.1/admin", "ssrf_blocked"),
        ("https://127.0.0.1:8443/internal", "ssrf_blocked"),
        ("http://169.254.169.254/latest/meta-data/", "ssrf_blocked"),
        ("http://10.0.0.15/secret", "ssrf_blocked"),
        ("http://172.16.5.4/config", "ssrf_blocked"),
        ("http://192.168.1.1/router", "ssrf_blocked"),
        ("http://0.0.0.0/", "ssrf_blocked"),
        ("http://[::1]/", "ssrf_blocked"),
        ("http://[::ffff:127.0.0.1]/", "ssrf_blocked"),
        ("http://224.0.0.1/", "ssrf_blocked"),
        ("https://93.184.216.34:22/", "ssrf_blocked"),
        ("http://93.184.216.34:6379/", "ssrf_blocked"),
        ("https://user:password@93.184.216.34/", "invalid_url"),
        ("ftp://93.184.216.34/pub", "invalid_url"),
    ],
)
async def test_service_blocks_ssrf_and_invalid_urls(blocked_url: str, expected_code: str):
    service = SecurityAuditService(redis_client=FakeAsyncRedis())  # type: ignore[arg-type]
    req = AuditRequest(url=blocked_url)
    with pytest.raises(AppError) as exc_info:
        await service.audit(req)
    assert exc_info.value.status_code == 400
    assert exc_info.value.code == expected_code


@pytest.mark.asyncio
async def test_service_blocks_dns_rebinding_to_private_ip():
    service = SecurityAuditService(redis_client=FakeAsyncRedis())  # type: ignore[arg-type]
    req = AuditRequest(url="https://internal.evil.example.com/api")

    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.240.0.12", 443)),
    ]
    loop = MagicMock()
    loop.getaddrinfo = AsyncMock(return_value=fake_addrinfo)

    with patch("app.core.ssrf.asyncio.get_running_loop", return_value=loop):
        with pytest.raises(AppError) as exc_info:
            await service.audit(req)

    assert exc_info.value.status_code == 400
    assert exc_info.value.code == "ssrf_blocked"


@pytest.mark.asyncio
async def test_service_blocks_ssrf_via_http_redirect_to_internal_metadata():
    """Verifies that a public URL redirecting (302) to 169.254.169.254 is blocked."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/iam"},
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as mock_http:
        service = SecurityAuditService(
            redis_client=FakeAsyncRedis(),  # type: ignore[arg-type]
            http_client=mock_http,
        )
        req = AuditRequest(url="https://93.184.216.34/start")
        with pytest.raises(AppError) as exc_info:
            await service.audit(req)

    assert exc_info.value.status_code == 400
    assert exc_info.value.code == "ssrf_blocked"


# =====================================================================
# 4. Security Headers & Score / Grade Calculation Algorithm Tests
# =====================================================================


@pytest.mark.parametrize(
    ("score", "expected_grade"),
    [
        (100, "A+"),
        (95, "A+"),
        (94, "A"),
        (90, "A"),
        (89, "B"),
        (80, "B"),
        (79, "C"),
        (70, "C"),
        (69, "D"),
        (60, "D"),
        (59, "F"),
        (25, "F"),
        (0, "F"),
    ],
)
def test_score_to_grade_boundaries(score: int, expected_grade: str):
    assert score_to_grade(score) == expected_grade


def test_calculate_security_score_all_grades_and_scenarios():
    valid_ssl = SSLInfo(
        enabled=True,
        valid=True,
        trusted_chain=True,
        hostname_match=True,
        expired=False,
        days_remaining=90,
        protocol="TLSv1.3",
    )
    clean_threat = ThreatIntelResult(is_malicious=False)

    # 1. Perfect headers + valid SSL => 100 (A+)
    headers_a_plus = audit_security_headers(STRONG_SECURITY_HEADERS)
    assert headers_a_plus.score == 100
    assert headers_a_plus.missing == []
    score, grade = calculate_security_score(valid_ssl, headers_a_plus, clean_threat)
    assert score == 100
    assert grade == "A+"

    # 2. Missing Referrer-Policy (-4) & Permissions-Policy (-4) => 92 (A)
    h_dict_a = {
        k: v
        for k, v in STRONG_SECURITY_HEADERS.items()
        if k not in {"Referrer-Policy", "Permissions-Policy"}
    }
    headers_a = audit_security_headers(h_dict_a)
    score, grade = calculate_security_score(valid_ssl, headers_a, clean_threat)
    assert score == 92
    assert grade == "A"

    # 3. Missing CSP (-10) & Permissions-Policy (-4) => 86 (B)
    h_dict_b = {
        k: v
        for k, v in STRONG_SECURITY_HEADERS.items()
        if k not in {"Content-Security-Policy", "Permissions-Policy"}
    }
    headers_b = audit_security_headers(h_dict_b)
    score, grade = calculate_security_score(valid_ssl, headers_b, clean_threat)
    assert score == 86
    assert grade == "B"

    # 4. Missing HSTS (-10), CSP (-10), Permissions-Policy (-4) => 76 (C)
    h_dict_c = {
        k: v
        for k, v in STRONG_SECURITY_HEADERS.items()
        if k not in {"Strict-Transport-Security", "Content-Security-Policy", "Permissions-Policy"}
    }
    headers_c = audit_security_headers(h_dict_c)
    score, grade = calculate_security_score(valid_ssl, headers_c, clean_threat)
    assert score == 76
    assert grade == "C"

    # 5. Valid SSL + Missing ALL 6 security headers (-40) => 60 (D)
    headers_empty = audit_security_headers({})
    assert headers_empty.score == 0
    assert len(headers_empty.missing) == 6
    score, grade = calculate_security_score(valid_ssl, headers_empty, clean_threat)
    assert score == 60
    assert grade == "D"

    # 6. Valid SSL + Missing all headers (-40) + Info leak headers (-5) => 55 (F)
    headers_leaked = audit_security_headers({"X-Powered-By": "PHP/8.2.0", "Server": "Apache/2.4.54"})
    assert "X-Powered-By" in headers_leaked.leaked_headers
    assert "Server" in headers_leaked.leaked_headers
    score, grade = calculate_security_score(valid_ssl, headers_leaked, clean_threat)
    assert score == 55
    assert grade == "F"

    # 7. Expired/Invalid SSL (-45) even with perfect headers => 55 (F)
    expired_ssl = SSLInfo(
        enabled=True,
        valid=False,
        trusted_chain=True,
        hostname_match=True,
        expired=True,
        days_remaining=-5,
        errors=["Certificate has expired."],
    )
    score, grade = calculate_security_score(expired_ssl, headers_a_plus, clean_threat)
    assert score == 55
    assert grade == "F"

    # 8. Malicious URL in URLhaus or OpenPhish => capped at <= 15 (F) even with valid SSL & headers
    malicious_threat = ThreatIntelResult(
        is_malicious=True,
        urlhaus_listed=True,
        openphish_listed=False,
        matched_feeds=["urlhaus"],
        matched_indicators=["https://93.184.216.34/malware.exe"],
    )
    score, grade = calculate_security_score(valid_ssl, headers_a_plus, malicious_threat)
    assert score <= 15
    assert grade == "F"


def test_audit_security_headers_weak_directives():
    weak_headers = {
        "Strict-Transport-Security": "max-age=3600",
        "Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
        "X-Content-Type-Options": "invalid",
        "X-Frame-Options": "ALLOW-FROM https://example.com",
        "Referrer-Policy": "unsafe-url",
        "Permissions-Policy": "geolocation=*",
    }
    res = audit_security_headers(weak_headers)
    assert res.missing == []
    assert all(res.details[k].status == "warn" for k in res.details)
    assert len(res.warnings) >= 6
    assert 0 < res.score < 100


# =====================================================================
# 5. URLhaus & OpenPhish Async Redis Sync & Lookup Tests
# =====================================================================


def test_parse_feed_entries_handles_text_and_csv():
    sample_feed = """
    # URLhaus / OpenPhish comment line
    https://Malicious.Example.com:443/Dropper.exe
    "101","2026-11-19","http://bad.phish.org:80/login/","online"
    phishing-domain.net
    """
    urls, hosts = parse_feed_entries(sample_feed)
    assert normalize_url_indicator("https://malicious.example.com/Dropper.exe") in urls
    assert normalize_url_indicator("http://bad.phish.org/login") in urls
    assert "malicious.example.com" in hosts
    assert "bad.phish.org" in hosts
    assert "phishing-domain.net" in hosts


@pytest.mark.asyncio
async def test_sync_and_check_threat_feeds_in_redis():
    fake_redis = FakeAsyncRedis()

    def feed_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == URLHAUS_FEED_URL:
            return httpx.Response(
                200,
                text="# URLhaus\nhttps://93.184.216.34/payload.bin\nhttp://malware.test.org/a\n",
            )
        if str(request.url) == OPENPHISH_FEED_URL:
            return httpx.Response(
                200,
                text="https://login.phish-bank.com/auth\n",
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(feed_handler)
    async with httpx.AsyncClient(transport=transport) as mock_http:
        service = SecurityAuditService(
            redis_client=fake_redis,  # type: ignore[arg-type]
            http_client=mock_http,
        )
        sync_res = await service.sync_threat_feeds()

        assert sync_res.synced is True
        assert sync_res.urlhaus_count >= 2
        assert sync_res.openphish_count >= 1
        assert sync_res.errors == []
        assert await fake_redis.get(REDIS_KEY_FEEDS_LAST_SYNC) is not None
        assert REDIS_KEY_URLHAUS_URLS in fake_redis.ttls
        assert REDIS_KEY_OPENPHISH_URLS in fake_redis.ttls

        # Match in URLhaus
        hit_uh = await service.check_threat_feeds("https://93.184.216.34/payload.bin", "93.184.216.34")
        assert hit_uh.is_malicious is True
        assert hit_uh.urlhaus_listed is True
        assert hit_uh.openphish_listed is False
        assert "urlhaus" in hit_uh.matched_feeds

        # Match in OpenPhish by host
        hit_op = await service.check_threat_feeds("https://login.phish-bank.com/other", "login.phish-bank.com")
        assert hit_op.is_malicious is True
        assert hit_op.openphish_listed is True
        assert "openphish" in hit_op.matched_feeds

        # Clean target
        clean = await service.check_threat_feeds("https://1.1.1.1/", "1.1.1.1")
        assert clean.is_malicious is False
        assert clean.matched_feeds == []


# =====================================================================
# 6. FastAPI Endpoint Integration Tests (/v1/audit)
# =====================================================================


def test_endpoint_requires_rapidapi_proxy_secret():
    with TestClient(app) as client:
        resp = client.post("/v1/audit", json={"url": "https://93.184.216.34"})
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "forbidden"


def test_endpoint_audit_healthy_target_returns_a_plus():
    fake_redis = FakeAsyncRedis()
    valid_der = build_test_certificate(
        subject_cn="93.184.216.34",
        issuer_cn="DigiCert Root CA",
        san_ips=["93.184.216.34"],
        not_before_offset=timedelta(days=-10),
        not_after_offset=timedelta(days=120),
    )
    valid_ssl = parse_and_validate_x509_cert(
        valid_der,
        hostname="93.184.216.34",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )

    def http_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers=STRONG_SECURITY_HEADERS, text="OK")

    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(http_handler))
    service = SecurityAuditService(redis_client=fake_redis, http_client=mock_http)  # type: ignore[arg-type]
    service.check_tls = AsyncMock(return_value=valid_ssl)  # type: ignore[method-assign]

    app.dependency_overrides[get_audit_service] = lambda: service

    with TestClient(app) as client:
        resp = client.post(
            "/v1/audit",
            headers=AUTH_HEADERS,
            json={"url": "https://93.184.216.34"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 100
    assert data["grade"] == "A+"
    assert data["ssl"]["valid"] is True
    assert data["ssl"]["expired"] is False
    assert data["headers"]["score"] == 100
    assert data["threat_intel"]["is_malicious"] is False
    assert "X-Request-ID" in resp.headers


def test_endpoint_audit_expired_ssl_and_missing_headers_returns_grade_f():
    fake_redis = FakeAsyncRedis()
    expired_der = build_test_certificate(
        subject_cn="93.184.216.34",
        issuer_cn="Test Root CA",
        san_ips=["93.184.216.34"],
        not_before_offset=timedelta(days=-100),
        not_after_offset=timedelta(days=-10),
    )
    expired_ssl = parse_and_validate_x509_cert(
        expired_der,
        hostname="93.184.216.34",
        protocol="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
        chain_trusted=False,
        verification_error="certificate has expired",
    )

    def http_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Server": "nginx/1.18.0"}, text="OK")

    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(http_handler))
    service = SecurityAuditService(redis_client=fake_redis, http_client=mock_http)  # type: ignore[arg-type]
    service.check_tls = AsyncMock(return_value=expired_ssl)  # type: ignore[method-assign]

    app.dependency_overrides[get_audit_service] = lambda: service

    with TestClient(app) as client:
        resp = client.post(
            "/v1/audit",
            headers=AUTH_HEADERS,
            json={"url": "https://93.184.216.34"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ssl"]["valid"] is False
    assert data["ssl"]["expired"] is True
    assert data["grade"] == "F"
    assert data["score"] < 60
    assert len(data["recommendations"]) > 0


def test_endpoint_blocks_ssrf_with_400():
    with TestClient(app) as client:
        resp = client.post(
            "/v1/audit",
            headers=AUTH_HEADERS,
            json={"url": "http://127.0.0.1:8080/internal"},
        )

    assert resp.status_code == 400
    body = resp.json()
    assert body["error"]["code"] == "ssrf_blocked"


@pytest.mark.asyncio
async def test_fetch_http_response_pins_resolved_ip_and_blocks_redirect_loops():
    seen_requests: list[httpx.Request] = []

    def loop_handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(302, headers={"Location": "/next"})

    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
    ]
    loop = MagicMock()
    loop.getaddrinfo = AsyncMock(return_value=fake_addrinfo)

    async with httpx.AsyncClient(transport=httpx.MockTransport(loop_handler)) as mock_http:
        service = SecurityAuditService(
            redis_client=FakeAsyncRedis(),  # type: ignore[arg-type]
            http_client=mock_http,
        )
        with patch("app.core.ssrf.asyncio.get_running_loop", return_value=loop):
            with pytest.raises(AppError) as exc_info:
                await service.audit(AuditRequest(url="https://example.com/start"))

    assert exc_info.value.status_code == 400
    assert exc_info.value.code == "too_many_redirects"
    assert len(seen_requests) == 6
    assert seen_requests[0].url.host == "93.184.216.34"
    assert seen_requests[0].headers["Host"] == "example.com"
    assert seen_requests[0].extensions.get("sni_hostname") == "example.com"


def test_endpoint_plain_http_and_feed_sync():
    fake_redis = FakeAsyncRedis()

    def http_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == URLHAUS_FEED_URL:
            return httpx.Response(200, text="http://93.184.216.34/bad\n")
        if str(request.url) == OPENPHISH_FEED_URL:
            return httpx.Response(200, text="http://phish.example.org/login\n")
        return httpx.Response(200, headers=STRONG_SECURITY_HEADERS, text="OK")

    mock_http = httpx.AsyncClient(transport=httpx.MockTransport(http_handler))
    service = SecurityAuditService(redis_client=fake_redis, http_client=mock_http)  # type: ignore[arg-type]
    app.dependency_overrides[get_audit_service] = lambda: service

    with TestClient(app) as client:
        sync_resp = client.post("/v1/audit/feeds/sync", headers=AUTH_HEADERS)
        assert sync_resp.status_code == 200
        assert sync_resp.json()["synced"] is True

        audit_resp = client.post(
            "/v1/audit",
            headers=AUTH_HEADERS,
            json={"url": "http://93.184.216.34/clean"},
        )
        assert audit_resp.status_code == 200
        body = audit_resp.json()
        assert body["ssl"]["enabled"] is False
        assert body["ssl"]["valid"] is False
        # Host 93.184.216.34 was in URLhaus feed above
        assert body["threat_intel"]["is_malicious"] is True
        assert body["grade"] == "F"


def test_x509_idn_punycode_san_and_wildcard_matching():
    der = build_test_certificate(
        subject_cn="xn--bcher-kva.example.com",
        issuer_cn="DigiCert Root CA",
        san_dns=["xn--bcher-kva.example.com", "*.xn--bcher-kva.example.com"],
        not_before_offset=timedelta(days=-5),
        not_after_offset=timedelta(days=60),
    )

    info_unicode = parse_and_validate_x509_cert(
        der,
        hostname="bücher.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info_unicode.valid is True
    assert info_unicode.hostname_match is True

    info_wildcard_unicode = parse_and_validate_x509_cert(
        der,
        hostname="shop.bücher.example.com",
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        chain_trusted=True,
    )
    assert info_wildcard_unicode.valid is True
    assert info_wildcard_unicode.hostname_match is True


@pytest.mark.asyncio
async def test_redirect_to_malformed_port_raises_400_instead_of_500():
    def bad_redirect_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"Location": "http://127.0.0.1:99999/admin"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(bad_redirect_handler)) as mock_http:
        service = SecurityAuditService(
            redis_client=FakeAsyncRedis(),  # type: ignore[arg-type]
            http_client=mock_http,
        )
        with pytest.raises(AppError) as exc_info:
            await service.audit(AuditRequest(url="https://93.184.216.34/start"))

    assert exc_info.value.status_code == 400
    assert exc_info.value.code == "invalid_url"


def test_ipv6_and_idn_target_pinning_and_indicator_normalization():
    pinned_url, host_header, sni_host = SecurityAuditService._build_pinned_target(
        "https://[2606:4700:4700::1111]:8443/path?x=1",
        "2606:4700:4700::1111",
    )
    assert pinned_url == "https://[2606:4700:4700::1111]:8443/path?x=1"
    assert host_header == "[2606:4700:4700::1111]:8443"
    assert sni_host == "2606:4700:4700::1111"

    norm_ipv6 = normalize_url_indicator("https://[2606:4700:4700::1111]:443/path/")
    assert norm_ipv6 == "https://[2606:4700:4700::1111]/path"

    pinned_idn, idn_host_hdr, idn_sni = SecurityAuditService._build_pinned_target(
        "https://점검.example.com/check",
        "93.184.216.34",
    )
    assert pinned_idn == "https://93.184.216.34/check"
    assert idn_host_hdr == "xn--c79ar63c.example.com"
    assert idn_sni == "xn--c79ar63c.example.com"

    assert (
        normalize_url_indicator("https://bücher.example.com:443/Login/")
        == "https://xn--bcher-kva.example.com/Login"
    )


def test_parse_feed_entries_exact_count_and_skips_malformed_lines():
    feed_text = "\n".join(
        [
            "# Feed with IDN, non-canonical port, and a corrupt line",
            "https://Bücher.Example.com:443/phish/",
            "http://broken.example.com:99999/badport",
            "http://[::1/malformed-ipv6",
            "https://93.184.216.34/malware.bin",
        ]
    )
    urls, hosts = parse_feed_entries(feed_text)
    assert len(urls) == 2
    assert "https://xn--bcher-kva.example.com/phish" in urls
    assert "https://93.184.216.34/malware.bin" in urls
    assert "xn--bcher-kva.example.com" in hosts
    assert "93.184.216.34" in hosts


def test_audit_security_headers_csp_subdomain_wildcard_and_comma_folded_headers():
    headers = {
        "Strict-Transport-Security": 'max-age="31536000"; includeSubDomains',
        "Content-Security-Policy": "default-src 'self'; script-src 'self' https://*.trusted-cdn.com; frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff, nosniff",
        "X-Frame-Options": "DENY, DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=()",
    }
    res = audit_security_headers(headers)
    assert res.score == 100
    assert res.warnings == []
    assert res.details["content-security-policy"].status == "pass"
    assert res.details["x-content-type-options"].status == "pass"
    assert res.details["x-frame-options"].status == "pass"

    # Multi-space wildcard frame-ancestors must NOT satisfy X-Frame-Options fallback
    res_bad_fa = audit_security_headers(
        {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors   *",
        }
    )
    assert res_bad_fa.details["x-frame-options"].status == "fail"
    assert "X-Frame-Options" in res_bad_fa.missing


