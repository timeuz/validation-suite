import asyncio
from functools import lru_cache
import re
from typing import Literal

import dns.asyncresolver
import dns.exception
import dns.resolver
from disposable_email_domains import blocklist as _EXTERNAL_DISPOSABLE_BLOCKLIST
from email_validator import EmailNotValidError, validate_email
import idna
import redis.asyncio as redis

from app.core.exceptions import AppError
from app.modules.mail_verify.schemas import (
    DomainReputation,
    EmailVerifyResponse,
    validate_email_syntax_str,
)

CACHE_KEY_PREFIX = "mail_verify:domain_rep:"
CACHE_TTL_SECONDS = 3600
DNS_LIFETIME_SECONDS = 3.0

_DMARC_PREFIX_RE = re.compile(r"^v\s*=\s*dmarc1\s*(?:;|$)", re.IGNORECASE)

_MULTI_PART_TLDS: frozenset[str] = frozenset(
    {
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "co.uk",
        "org.uk",
        "ac.uk",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.au",
        "net.au",
        "org.au",
        "com.ar",
        "com.mx",
        "co.nz",
        "co.za",
        "co.in",
        "com.tr",
        "com.cn",
        "com.tw",
        "com.hk",
        "com.sg",
        "eu.org",
    }
)

_TYPO_TLDS_FOR_COM: frozenset[str] = frozenset(
    {"co", "con", "cm", "om", "cmo", "ocm", "comm", "vom", "xom", "cim", "comn", "conm"}
)

_TYPO_TLDS_FOR_COM_BR: frozenset[str] = frozenset(
    {"com.b", "com.r", "con.br", "cmo.br", "ocm.br", "com.brr", "co.br", "cm.br", "om.br"}
)

COMMON_DOMAINS: tuple[str, ...] = (
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "protonmail.com",
    "proton.me",
    "live.com",
    "msn.com",
    "aol.com",
    "zoho.com",
    "gmx.com",
    "ymail.com",
    "uol.com.br",
    "bol.com.br",
    "terra.com.br",
    "globo.com",
    "outlook.com.br",
    "yahoo.com.br",
)

_FALLBACK_DISPOSABLE_DOMAINS: frozenset[str] = frozenset(
    {
        "mailinator.com",
        "10minutemail.com",
        "guerrillamail.com",
        "tempmail.com",
        "temp-mail.org",
        "yopmail.com",
        "trashmail.com",
        "sharklasers.com",
        "getnada.com",
        "maildrop.cc",
        "dispostable.com",
        "throwawaymail.com",
        "fakeinbox.com",
        "mailnesia.com",
        "mintemail.com",
    }
)


_KNOWN_TYPO_DOMAINS: frozenset[str] = frozenset(
    {
        "gmial.com",
        "gmal.com",
        "gmai.com",
        "gnail.com",
        "gmail.con",
        "gmail.co",
        "gmaill.com",
        "gmaillk.com",
        "gmailot.com",
        "gmayll.com",
        "hotmial.com",
        "hotmai.com",
        "hotmal.com",
        "hotmail.con",
        "gotmail.com",
        "h0tmaii.com",
        "hmamail.com",
        "hormails.com",
        "outlok.com",
        "outllok.com",
        "outlook.con",
        "yaho.com",
        "yahooo.com",
        "yahoo.con",
        "iclod.com",
        "icloud.con",
        "icloulb.com",
        "icousd.com",
        "protonmal.com",
    }
)


def _to_ascii_domain(domain: str) -> str:
    """Converte domínio internacionalizado (IDN) para punycode A-label usando IDNA 2008 / UTS #46."""
    cleaned = domain.strip().lower().rstrip(".")
    if not cleaned:
        return ""
    if cleaned.isascii():
        return cleaned
    try:
        return idna.encode(cleaned, uts46=True).decode("ascii").lower()
    except Exception:
        try:
            return cleaned.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return cleaned


def _get_organizational_domain(ascii_domain: str) -> str:
    """Retorna o domínio organizacional base (ex: 'sub.mail.example.com' -> 'example.com')."""
    labels = [lbl for lbl in ascii_domain.strip().lower().rstrip(".").split(".") if lbl]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    min_labels = 3 if last_two in _MULTI_PART_TLDS else 2
    if len(labels) <= min_labels:
        return ".".join(labels)
    return ".".join(labels[-min_labels:])


@lru_cache(maxsize=1)
def load_disposable_blocklist() -> frozenset[str]:
    """Carrega e normaliza a blocklist de domínios de e-mail descartáveis em memória."""
    normalized = {str(d).strip().lower().rstrip(".") for d in _EXTERNAL_DISPOSABLE_BLOCKLIST if d}
    return frozenset((normalized | _FALLBACK_DISPOSABLE_DOMAINS) - _KNOWN_TYPO_DOMAINS)


def is_disposable_domain(domain: str) -> bool:
    """Verifica se o domínio (ou qualquer domínio pai) pertence à blocklist de descartáveis."""
    cleaned = _to_ascii_domain(domain)
    if not cleaned:
        return False
    blocklist = load_disposable_blocklist()
    if cleaned in blocklist:
        return True
    parts = cleaned.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in blocklist:
            return True
    return False


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calcula a distância de edição de Levenshtein entre duas strings."""
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, start=1):
        current_row = [i]
        for j, c2 in enumerate(s2, start=1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def suggest_domain(domain: str, max_distance: int = 2) -> str | None:
    """Sugere correção para domínios populares com erro de digitação via distância de Levenshtein."""
    cleaned = _to_ascii_domain(domain)
    if not cleaned or cleaned in COMMON_DOMAINS or is_disposable_domain(cleaned):
        return None

    cleaned_sld, _, cleaned_tld = cleaned.partition(".")
    best_match: str | None = None
    best_distance = max_distance + 1

    for candidate in COMMON_DOMAINS:
        dist = levenshtein_distance(cleaned, candidate)
        if dist == 0 or dist > max_distance:
            continue

        candidate_sld, _, candidate_tld = candidate.partition(".")
        if cleaned_sld == candidate_sld:
            if candidate_tld == "com" and cleaned_tld not in _TYPO_TLDS_FOR_COM:
                continue
            if candidate_tld == "com.br" and cleaned_tld not in _TYPO_TLDS_FOR_COM_BR:
                continue
            if candidate_tld not in {"com", "com.br"} and dist > 1:
                continue

        is_transposition = sorted(cleaned) == sorted(candidate)
        if dist == 2 and not (is_transposition or cleaned[0] == candidate[0]):
            continue
        if len(candidate_sld) <= 4 and dist == 2 and not is_transposition:
            continue
        if len(candidate_sld) <= 3 and not (is_transposition or cleaned[0] == candidate[0]):
            continue
        if dist < best_distance:
            best_distance = dist
            best_match = candidate

    return best_match


def suggest_email(local_part: str, domain: str) -> str | None:
    """Retorna sugestão completa 'local_part@dominio_sugerido' caso detecte typo no domínio."""
    if not local_part or not domain:
        return None
    suggested_dom = suggest_domain(domain)
    if suggested_dom is None:
        return None
    return f"{local_part}@{suggested_dom}"


def _extract_txt_value(rdata: object) -> str:
    """Extrai e concatena fragmentos de um registro DNS TXT sem aspas envolventes."""
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        parts: list[str] = []
        for chunk in strings:
            if isinstance(chunk, (bytes, bytearray)):
                parts.append(chunk.decode("utf-8", errors="replace"))
            else:
                parts.append(str(chunk))
        return "".join(parts).strip()

    to_text = getattr(rdata, "to_text", None)
    text = str(to_text()).strip() if callable(to_text) else str(rdata).strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        text = re.sub(r'"\s+"', "", text[1:-1])
    return text.strip()


async def resolve_mx_records(domain: str) -> tuple[list[str], bool]:
    """Resolve registros MX de forma assíncrona (sem qualquer conexão SMTP na porta 25)."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "MX", lifetime=DNS_LIFETIME_SECONDS)
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, dns.resolver.NoNameservers, TimeoutError):
        return [], True
    except (dns.exception.DNSException, Exception):
        return [], False

    parsed: list[tuple[int, str]] = []
    for rdata in answers:
        pref = int(getattr(rdata, "preference", 0))
        exchange_raw = getattr(rdata, "exchange", rdata)
        exchange = str(exchange_raw).strip().rstrip(".").lower()
        # RFC 7505: Null MX ("0 .") indica que o domínio não aceita e-mails.
        if exchange:
            parsed.append((pref, exchange))

    parsed.sort(key=lambda item: (item[0], item[1]))
    seen: set[str] = set()
    mx_hosts: list[str] = []
    for _, host in parsed:
        if host not in seen:
            seen.add(host)
            mx_hosts.append(host)
    return mx_hosts, False


async def resolve_spf_record(domain: str) -> tuple[str | None, bool]:
    """Resolve registros TXT do domínio em busca de política SPF (v=spf1)."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "TXT", lifetime=DNS_LIFETIME_SECONDS)
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, dns.resolver.NoNameservers, TimeoutError):
        return None, True
    except (dns.exception.DNSException, Exception):
        return None, False

    for rdata in answers:
        txt = _extract_txt_value(rdata)
        lower = txt.lower()
        if lower == "v=spf1" or (lower.startswith("v=spf1") and lower[6:7].isspace()):
            return txt, False
    return None, False


async def _query_dmarc_txt(target_domain: str) -> tuple[str | None, bool]:
    """Consulta '_dmarc.<target_domain>' em busca de registro TXT DMARC (v=DMARC1)."""
    dmarc_qname = f"_dmarc.{target_domain}"
    try:
        answers = await dns.asyncresolver.resolve(dmarc_qname, "TXT", lifetime=DNS_LIFETIME_SECONDS)
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, dns.resolver.NoNameservers, TimeoutError):
        return None, True
    except (dns.exception.DNSException, Exception):
        return None, False

    for rdata in answers:
        txt = _extract_txt_value(rdata)
        if _DMARC_PREFIX_RE.match(txt):
            return txt, False
    return None, False


async def resolve_dmarc_record(domain: str) -> tuple[str | None, bool]:
    """Resolve registros TXT em '_dmarc.<domain>' com fallback organizacional RFC 7489 §6.6.3."""
    cleaned = _to_ascii_domain(domain)
    if not cleaned:
        return None, False

    record, timed_out = await _query_dmarc_txt(cleaned)
    if record is not None or timed_out:
        return record, timed_out

    org_domain = _get_organizational_domain(cleaned)
    if org_domain and org_domain != cleaned:
        return await _query_dmarc_txt(org_domain)

    return None, False


def calculate_reputation(
    *,
    has_mx: bool,
    has_spf: bool,
    has_dmarc: bool,
    is_disposable: bool,
) -> tuple[int, Literal["high", "medium", "low", "blocked"]]:
    """Calcula score (0-100) e status de reputação do domínio com base em MX, SPF, DMARC e blocklist."""
    if is_disposable:
        return 0, "blocked"
    if not has_mx:
        return 10, "low"

    score = 50
    if has_spf:
        score += 25
    if has_dmarc:
        score += 25

    status: Literal["high", "medium", "low", "blocked"] = "high" if score >= 90 else "medium"
    return score, status


async def get_domain_reputation(
    domain: str,
    redis_client: redis.Redis | None = None,
) -> tuple[DomainReputation, bool]:
    """Obtém a reputação do domínio via cache Redis ou resolução DNS assíncrona."""
    normalized_domain = domain.strip().lower().rstrip(".")
    ascii_domain = _to_ascii_domain(normalized_domain)

    cache_key = f"{CACHE_KEY_PREFIX}{ascii_domain}"

    if redis_client is not None:
        try:
            cached_payload = await redis_client.get(cache_key)
            if cached_payload:
                if isinstance(cached_payload, (bytes, bytearray)):
                    cached_payload = cached_payload.decode("utf-8")
                reputation = DomainReputation.model_validate_json(cached_payload)
                if reputation.domain != normalized_domain:
                    reputation = reputation.model_copy(update={"domain": normalized_domain})
                return reputation, True
        except Exception:
            pass

    (mx_records, mx_timed_out), (spf_record, spf_timed_out), (dmarc_record, dmarc_timed_out) = await asyncio.gather(
        resolve_mx_records(ascii_domain),
        resolve_spf_record(ascii_domain),
        resolve_dmarc_record(ascii_domain),
    )

    has_mx = len(mx_records) > 0
    has_spf = spf_record is not None
    has_dmarc = dmarc_record is not None
    disposable = is_disposable_domain(ascii_domain)
    score, status = calculate_reputation(
        has_mx=has_mx,
        has_spf=has_spf,
        has_dmarc=has_dmarc,
        is_disposable=disposable,
    )

    reputation = DomainReputation(
        domain=normalized_domain,
        has_mx=has_mx,
        mx_records=mx_records,
        has_spf=has_spf,
        spf_record=spf_record,
        has_dmarc=has_dmarc,
        dmarc_record=dmarc_record,
        is_disposable=disposable,
        reputation_score=score,
        reputation_status=status,
    )

    any_timed_out = mx_timed_out or spf_timed_out or dmarc_timed_out
    if redis_client is not None and not any_timed_out:
        try:
            await redis_client.set(cache_key, reputation.model_dump_json(), ex=CACHE_TTL_SECONDS)
        except Exception:
            pass

    return reputation, False


async def verify_email(
    email: str,
    redis_client: redis.Redis | None = None,
) -> EmailVerifyResponse:
    """Executa a pipeline completa de verificação de higiene de e-mail sem handshake SMTP."""
    if not isinstance(email, str) or not email.strip():
        raise AppError(422, "invalid_email", "Email address cannot be empty.")

    raw = email.strip()
    try:
        normalized_email = validate_email_syntax_str(raw)
        validated = validate_email(normalized_email, check_deliverability=False, strict=True)
        syntax_valid = True
        local_part = validated.local_part
        domain = normalized_email.split("@", 1)[1]
    except (EmailNotValidError, ValueError):
        syntax_valid = False
        if "@" in raw:
            local_part, domain_raw = raw.rsplit("@", 1)
            domain = domain_raw.strip().lower().rstrip(".")
        else:
            local_part, domain = raw, ""
        did_you_mean = suggest_email(local_part, domain) if local_part and domain else None
        disposable = is_disposable_domain(domain) if domain else False
        return EmailVerifyResponse(
            email=raw,
            local_part=local_part,
            domain=domain,
            is_valid=False,
            syntax_valid=False,
            is_disposable=disposable,
            has_mx=False,
            mx_records=[],
            has_spf=False,
            spf_record=None,
            has_dmarc=False,
            dmarc_record=None,
            did_you_mean=did_you_mean,
            reputation_score=0,
            reputation_status="invalid",
            cached=False,
        )

    did_you_mean = suggest_email(local_part, domain)
    reputation, cached = await get_domain_reputation(domain, redis_client=redis_client)
    is_valid = syntax_valid and reputation.has_mx and not reputation.is_disposable

    return EmailVerifyResponse(
        email=normalized_email,
        local_part=local_part,
        domain=domain,
        is_valid=is_valid,
        syntax_valid=syntax_valid,
        is_disposable=reputation.is_disposable,
        has_mx=reputation.has_mx,
        mx_records=reputation.mx_records,
        has_spf=reputation.has_spf,
        spf_record=reputation.spf_record,
        has_dmarc=reputation.has_dmarc,
        dmarc_record=reputation.dmarc_record,
        did_you_mean=did_you_mean,
        reputation_score=reputation.reputation_score,
        reputation_status=reputation.reputation_status,
        cached=cached,
    )
