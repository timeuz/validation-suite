import asyncio
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch

_PROJECT_ROOT = str(Path(__file__).resolve().parents[3])
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import dns.exception
import dns.resolver
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.core.exceptions import AppError, RequestIDMiddleware, register_exception_handlers
from app.core.redis_client import get_redis
from app.modules.mail_verify.router import router
from app.modules.mail_verify.schemas import EmailVerifyRequest
from app.modules.mail_verify.service import (
    CACHE_KEY_PREFIX,
    CACHE_TTL_SECONDS,
    is_disposable_domain,
    levenshtein_distance,
    load_disposable_blocklist,
    suggest_domain,
    suggest_email,
    verify_email,
)


class FakeMXRdata:
    def __init__(self, preference: int, exchange: str):
        self.preference = preference
        self.exchange = exchange


class FakeTXTRdata:
    def __init__(self, *chunks: bytes | str):
        self.strings = tuple(c.encode("utf-8") if isinstance(c, str) else c for c in chunks)


class FakeRedis:
    """Mock assíncrono em memória compatível com redis.asyncio.Redis."""

    def __init__(self):
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


def _build_test_app(fake_redis: FakeRedis) -> FastAPI:
    test_app = FastAPI()
    test_app.add_middleware(RequestIDMiddleware)
    register_exception_handlers(test_app)
    test_app.include_router(router, prefix="/v1/email")
    test_app.dependency_overrides[get_redis] = lambda: fake_redis
    return test_app


# ---------------------------------------------------------------------------
# 1. Testes de Validação Sintática (schemas.py)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_email,expected",
    [
        ("user@gmail.com", "user@gmail.com"),
        ("  User.Name+tag@Example.COM  ", "User.Name+tag@example.com"),
        ("contato@empresa.com.br", "contato@empresa.com.br"),
        ("joão@münchen.de", "joão@münchen.de"),
    ],
)
def test_schema_valid_emails(raw_email: str, expected: str):
    req = EmailVerifyRequest(email=raw_email)
    assert req.email == expected


@pytest.mark.parametrize(
    "invalid_email",
    [
        "",
        "   ",
        "plainaddress",
        "@missing-local.com",
        "missing-domain@",
        "two@@signs.com",
        "user@localhost",
        "user@.leadingdot.com",
        "user@trailingdot.com.",
        "user@double..dot.com",
        ".leadingdot@example.com",
        "trailingdot.@example.com",
        "double..dot@example.com",
        "space in@example.com",
        "user@space in.com",
        "user\x00null@example.com",
        "user\nnewline@example.com",
        "user@domain.123",
        "user@domain.c",
        "user@example。com",
        "user@xn--invalid---punycode.com",
        "user@r3---sn-ab5l6nzk.googlevideo.com",
        f"{'a' * 65}@example.com",
        f"{'a' * 64}@{'b' * 62}.{'c' * 62}.{'d' * 61}.com",
        f"user@{'a' * 250}.com",
    ],
)
def test_schema_rejects_invalid_syntax(invalid_email: str):
    with pytest.raises(ValidationError):
        EmailVerifyRequest(email=invalid_email)


# ---------------------------------------------------------------------------
# 2. Testes de Distância de Levenshtein e Sugestões 'did_you_mean'
# ---------------------------------------------------------------------------


def test_levenshtein_distance_calculations():
    assert levenshtein_distance("", "") == 0
    assert levenshtein_distance("gmail.com", "gmail.com") == 0
    assert levenshtein_distance("", "abc") == 3
    assert levenshtein_distance("gmal.com", "gmail.com") == 1
    assert levenshtein_distance("gmial.com", "gmail.com") == 2
    assert levenshtein_distance("hotmial.com", "hotmail.com") == 2


@pytest.mark.parametrize(
    "typo_domain,expected_domain",
    [
        ("gmial.com", "gmail.com"),
        ("gmal.com", "gmail.com"),
        ("gmail.con", "gmail.com"),
        ("gmai.com", "gmail.com"),
        ("gnail.com", "gmail.com"),
        ("hotmial.com", "hotmail.com"),
        ("hotmai.com", "hotmail.com"),
        ("outlok.com", "outlook.com"),
        ("outllok.com", "outlook.com"),
        ("yaho.com", "yahoo.com"),
        ("yahooo.com", "yahoo.com"),
        ("iclod.com", "icloud.com"),
        ("protonmal.com", "protonmail.com"),
        ("lvie.com", "live.com"),
        ("gotmail.com", "hotmail.com"),
        ("uol.con.br", "uol.com.br"),
    ],
)
def test_suggest_domain_detects_typos(typo_domain: str, expected_domain: str):
    assert suggest_domain(typo_domain) == expected_domain
    assert suggest_email("alice", typo_domain) == f"alice@{expected_domain}"


@pytest.mark.parametrize(
    "valid_or_custom_domain",
    [
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "ymail.com",
        "live.com",
        "yahoo.ca",
        "yahoo.com.ar",
        "yahoo.com.mx",
        "outlook.com.ar",
        "outlook.com.au",
        "uol.com",
        "bol.com",
        "example.com",
        "company.io",
        "cnn.com",
        "ibm.com",
        "mailinator.com",
        "",
    ],
)
def test_suggest_domain_returns_none_for_exact_or_unrelated_domains(valid_or_custom_domain: str):
    assert suggest_domain(valid_or_custom_domain) is None


# ---------------------------------------------------------------------------
# 3. Testes de Detecção de E-mails Descartáveis (Blocklist)
# ---------------------------------------------------------------------------


def test_disposable_blocklist_loaded_and_detects_domains():
    blocklist = load_disposable_blocklist()
    assert len(blocklist) > 1000
    assert is_disposable_domain("mailinator.com") is True
    assert is_disposable_domain("MAILINATOR.COM.") is True
    assert is_disposable_domain("10minutemail.com") is True
    assert is_disposable_domain("guerrillamail.com") is True
    assert is_disposable_domain("yopmail.com") is True
    # Subdomínios de provedores descartáveis também devem ser bloqueados
    assert is_disposable_domain("sub.mailinator.com") is True
    assert is_disposable_domain("mail.10minutemail.com") is True
    # Domínios IDN descartáveis na blocklist (ex: xn--d-bga.net <-> dé.net)
    assert is_disposable_domain("xn--d-bga.net") is True
    assert is_disposable_domain("dé.net") is True
    assert is_disposable_domain("sub.dé.net") is True
    # Domínios legítimos não devem estar na blocklist
    assert is_disposable_domain("gmail.com") is False
    assert is_disposable_domain("outlook.com") is False
    assert is_disposable_domain("empresa.com.br") is False
    assert is_disposable_domain("") is False


# ---------------------------------------------------------------------------
# 4. Testes do Serviço com Mock de DNS Assíncrono e Cache Redis
# ---------------------------------------------------------------------------


def test_verify_email_full_dns_records_and_redis_cache():
    async def _run():
        fake_redis = FakeRedis()
        dns_call_count = 0

        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            nonlocal dns_call_count
            dns_call_count += 1
            if qname == "example.com" and rdtype == "MX":
                return [
                    FakeMXRdata(20, "mx2.example.com."),
                    FakeMXRdata(10, "mx1.example.com."),
                ]
            if qname == "example.com" and rdtype == "TXT":
                return [
                    FakeTXTRdata("google-site-verification=xyz123"),
                    FakeTXTRdata(b"v=spf1 include:_spf.example.com ", b"-all"),
                ]
            if qname == "_dmarc.example.com" and rdtype == "TXT":
                return [FakeTXTRdata("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")]
            raise dns.resolver.NoAnswer()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            # 1ª chamada: cache miss -> consulta DNS e grava no Redis
            res1 = await verify_email("Alice@Example.com", redis_client=fake_redis)
            assert res1.email == "Alice@example.com"
            assert res1.local_part == "Alice"
            assert res1.domain == "example.com"
            assert res1.syntax_valid is True
            assert res1.is_disposable is False
            assert res1.has_mx is True
            assert res1.mx_records == ["mx1.example.com", "mx2.example.com"]
            assert res1.has_spf is True
            assert res1.spf_record == "v=spf1 include:_spf.example.com -all"
            assert res1.has_dmarc is True
            assert res1.dmarc_record == "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
            assert res1.did_you_mean is None
            assert res1.reputation_score == 100
            assert res1.reputation_status == "high"
            assert res1.is_valid is True
            assert res1.cached is False
            assert dns_call_count == 3
            assert fake_redis.set_calls == 1
            assert fake_redis.ttls[f"{CACHE_KEY_PREFIX}example.com"] == CACHE_TTL_SECONDS

            # 2ª chamada para o mesmo domínio: cache hit -> zero chamadas DNS extras
            res2 = await verify_email("bob@example.com", redis_client=fake_redis)
            assert res2.email == "bob@example.com"
            assert res2.cached is True
            assert res2.is_valid is True
            assert res2.reputation_score == 100
            assert dns_call_count == 3

    asyncio.run(_run())


def test_verify_email_disposable_domain_blocked():
    async def _run():
        fake_redis = FakeRedis()

        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            if rdtype == "MX":
                return [FakeMXRdata(10, "mail.mailinator.com.")]
            raise dns.resolver.NoAnswer()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await verify_email("tempuser@mailinator.com", redis_client=fake_redis)
            assert res.syntax_valid is True
            assert res.is_disposable is True
            assert res.has_mx is True
            assert res.is_valid is False
            assert res.reputation_score == 0
            assert res.reputation_status == "blocked"
            assert res.did_you_mean is None

    asyncio.run(_run())


def test_verify_email_typo_domain_and_nxdomain():
    async def _run():
        fake_redis = FakeRedis()

        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            raise dns.resolver.NXDOMAIN()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await verify_email("john.doe@gmial.com", redis_client=fake_redis)
            assert res.email == "john.doe@gmial.com"
            assert res.syntax_valid is True
            assert res.did_you_mean == "john.doe@gmail.com"
            assert res.has_mx is False
            assert res.mx_records == []
            assert res.has_spf is False
            assert res.has_dmarc is False
            assert res.is_valid is False
            assert res.reputation_score == 10
            assert res.reputation_status == "low"

    asyncio.run(_run())


def test_verify_email_null_mx_rfc7505():
    async def _run():
        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            if rdtype == "MX":
                return [FakeMXRdata(0, ".")]
            raise dns.resolver.NoAnswer()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await verify_email("user@nomail.example.org", redis_client=None)
            assert res.has_mx is False
            assert res.mx_records == []
            assert res.is_valid is False
            assert res.reputation_status == "low"

    asyncio.run(_run())


def test_verify_email_dns_timeout_does_not_poison_cache():
    async def _run():
        fake_redis = FakeRedis()

        async def mock_resolve_all_timeout(qname: str, rdtype: str, **kwargs):
            raise dns.exception.Timeout()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve_all_timeout):
            res = await verify_email("user@slowdns.org", redis_client=fake_redis)
            assert res.has_mx is False
            assert res.is_valid is False
            # Em caso de timeout de rede no MX, não deve gravar falso negativo no Redis
            assert fake_redis.set_calls == 0

        # Timeout parcial apenas em SPF ou DMARC (quando MX responde) também não deve envenenar o Redis
        async def mock_resolve_spf_timeout(qname: str, rdtype: str, **kwargs):
            if rdtype == "MX":
                return [FakeMXRdata(10, "mx.partial-timeout.org.")]
            if qname == "partial-timeout.org" and rdtype == "TXT":
                raise dns.resolver.LifetimeTimeout()
            if qname == "_dmarc.partial-timeout.org" and rdtype == "TXT":
                return [FakeTXTRdata("v=DMARC1; p=reject")]
            raise dns.resolver.NoAnswer()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve_spf_timeout):
            res_partial = await verify_email("user@partial-timeout.org", redis_client=fake_redis)
            assert res_partial.has_mx is True
            assert res_partial.has_spf is False
            assert res_partial.has_dmarc is True
            assert fake_redis.set_calls == 0

        # Falha transitória NoNameservers (SERVFAIL) também não deve envenenar o Redis
        async def mock_resolve_servfail(qname: str, rdtype: str, **kwargs):
            raise dns.resolver.NoNameservers()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve_servfail):
            res_servfail = await verify_email("user@servfail.org", redis_client=fake_redis)
            assert res_servfail.has_mx is False
            assert fake_redis.set_calls == 0

    asyncio.run(_run())


def test_verify_email_idna2008_uts46_and_subdomain_dmarc_fallback():
    async def _run():
        fake_redis = FakeRedis()
        queried: list[tuple[str, str]] = []

        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            queried.append((qname, rdtype))
            # IDNA 2008: faß.de -> xn--fa-hia.de (e não fass.de do IDNA 2003)
            if qname == "xn--fa-hia.de" and rdtype == "MX":
                return [FakeMXRdata(10, "mx.xn--fa-hia.de.")]
            if qname == "xn--fa-hia.de" and rdtype == "TXT":
                return [FakeTXTRdata("v=spf1 -all")]
            if qname == "_dmarc.xn--fa-hia.de" and rdtype == "TXT":
                return [FakeTXTRdata("v=DMARC1; p=reject")]

            # Subdomínio multi-nível com fallback DMARC para o domínio organizacional (RFC 7489 §6.6.3)
            if qname == "mail.dept.example.com" and rdtype == "MX":
                return [FakeMXRdata(10, "mx.dept.example.com.")]
            if qname == "mail.dept.example.com" and rdtype == "TXT":
                return [FakeTXTRdata("v=spf1 mx -all")]
            if qname == "_dmarc.mail.dept.example.com" and rdtype == "TXT":
                raise dns.resolver.NXDOMAIN()
            if qname == "_dmarc.example.com" and rdtype == "TXT":
                return [
                    FakeTXTRdata("v=DMARC1 is not a valid dmarc without semicolon"),
                    FakeTXTRdata("v=DMARC1 ; p=quarantine"),
                ]
            raise dns.resolver.NoAnswer()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            res_idn = await verify_email("user@faß.de", redis_client=fake_redis)
            assert res_idn.is_valid is True
            assert res_idn.domain == "faß.de"
            assert res_idn.reputation_score == 100
            assert ("xn--fa-hia.de", "MX") in queried
            assert ("fass.de", "MX") not in queried

            # Consulta via punycode explícito deve reutilizar o mesmo cache Redis
            res_puny = await verify_email("user@xn--fa-hia.de", redis_client=fake_redis)
            assert res_puny.is_valid is True
            assert res_puny.cached is True
            assert res_puny.domain == "xn--fa-hia.de"

            # Subdomínio multi-nível herda política DMARC de _dmarc.example.com
            res_sub = await verify_email("user@mail.dept.example.com", redis_client=fake_redis)
            assert res_sub.is_valid is True
            assert res_sub.has_mx is True
            assert res_sub.has_spf is True
            assert res_sub.has_dmarc is True
            assert res_sub.dmarc_record == "v=DMARC1 ; p=quarantine"
            assert res_sub.reputation_score == 100

    asyncio.run(_run())


def test_verify_email_edge_cases_and_redis_failure_resilience():
    async def _run():
        # String vazia deve lançar AppError 422
        with pytest.raises(AppError) as exc_info:
            await verify_email("   ")
        assert exc_info.value.status_code == 422

        # Chamada direta ao service com sintaxe inválida retorna syntax_valid=False
        invalid_res = await verify_email("user..double@gmial.com")
        assert invalid_res.syntax_valid is False
        assert invalid_res.is_valid is False
        assert invalid_res.reputation_status == "invalid"
        assert invalid_res.did_you_mean == "user..double@gmail.com"

        # Falha no Redis não deve impedir a verificação via DNS
        broken_redis = AsyncMock()
        broken_redis.get.side_effect = ConnectionError("Redis offline")
        broken_redis.set.side_effect = ConnectionError("Redis offline")

        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            if rdtype == "MX":
                return [FakeMXRdata(10, "mx.resilient.org.")]
            raise dns.resolver.NoAnswer()

        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            res = await verify_email("ok@resilient.org", redis_client=broken_redis)
            assert res.is_valid is True
            assert res.has_mx is True
            assert res.reputation_score == 50
            assert res.reputation_status == "medium"

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# 5. Testes de Integração do Endpoint FastAPI POST /v1/email/verify
# ---------------------------------------------------------------------------


def test_router_verify_endpoint_success_and_validation_error():
    async def _run():
        fake_redis = FakeRedis()
        test_app = _build_test_app(fake_redis)

        async def mock_resolve(qname: str, rdtype: str, **kwargs):
            if qname == "gmail.com" and rdtype == "MX":
                return [FakeMXRdata(5, "gmail-smtp-in.l.google.com.")]
            if qname == "gmail.com" and rdtype == "TXT":
                return [FakeTXTRdata("v=spf1 redirect=_spf.google.com")]
            if qname == "_dmarc.gmail.com" and rdtype == "TXT":
                return [FakeTXTRdata("v=DMARC1; p=none; sp=quarantine")]
            raise dns.resolver.NXDOMAIN()

        transport = ASGITransport(app=test_app)
        with patch("app.modules.mail_verify.service.dns.asyncresolver.resolve", side_effect=mock_resolve):
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                # 1. E-mail válido
                resp = await client.post("/v1/email/verify", json={"email": "dev@gmail.com"})
                assert resp.status_code == 200
                body = resp.json()
                assert body["is_valid"] is True
                assert body["has_mx"] is True
                assert body["has_spf"] is True
                assert body["has_dmarc"] is True
                assert body["is_disposable"] is False
                assert body["reputation_score"] == 100

                # 2. E-mail com erro de digitação no domínio
                resp_typo = await client.post("/v1/email/verify", json={"email": "dev@gmial.com"})
                assert resp_typo.status_code == 200
                body_typo = resp_typo.json()
                assert body_typo["did_you_mean"] == "dev@gmail.com"
                assert body_typo["is_valid"] is False

                # 3. E-mail descartável
                resp_disp = await client.post("/v1/email/verify", json={"email": "anon@yopmail.com"})
                assert resp_disp.status_code == 200
                body_disp = resp_disp.json()
                assert body_disp["is_disposable"] is True
                assert body_disp["is_valid"] is False
                assert body_disp["reputation_status"] == "blocked"

                # 4. E-mail com sintaxe inválida -> 422 validation_error
                resp_bad = await client.post("/v1/email/verify", json={"email": "not-an-email"})
                assert resp_bad.status_code == 422
                err_body = resp_bad.json()
                assert err_body["error"]["code"] == "validation_error"
                assert "X-Request-ID" in resp_bad.headers

    asyncio.run(_run())


def test_architectural_constraints_no_smtp_and_core_isolation():
    module_dir = Path(__file__).resolve().parent
    for filename in ("schemas.py", "service.py", "router.py"):
        source = (module_dir / filename).read_text(encoding="utf-8")
        assert "smtplib" not in source
        assert "aiosmtplib" not in source
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import app.core", "from app.core")):
                assert "app.core.redis_client" in stripped or "app.core.exceptions" in stripped

