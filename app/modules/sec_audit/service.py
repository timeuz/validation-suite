import asyncio
from datetime import datetime, timezone
import ipaddress
import re
import ssl
from urllib.parse import urljoin, urlparse
import uuid

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID
import httpx
import redis.asyncio as redis

from app.core.exceptions import AppError
from app.core.ssrf import validate_url
from app.modules.sec_audit.schemas import (
    AuditRequest,
    AuditResponse,
    FeedSyncResponse,
    HeaderFinding,
    HeadersAuditResult,
    SecurityGrade,
    SSLInfo,
    ThreatIntelResult,
)

URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

REDIS_KEY_URLHAUS_URLS = "sec_audit:feeds:urlhaus:urls"
REDIS_KEY_URLHAUS_HOSTS = "sec_audit:feeds:urlhaus:hosts"
REDIS_KEY_OPENPHISH_URLS = "sec_audit:feeds:openphish:urls"
REDIS_KEY_OPENPHISH_HOSTS = "sec_audit:feeds:openphish:hosts"
REDIS_KEY_FEEDS_LAST_SYNC = "sec_audit:feeds:last_sync"

FEED_TTL_SECONDS = 3600
REDIS_BATCH_SIZE = 1000
MAX_REDIRECTS = 5

DEPRECATED_TLS_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}
SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
    "no-referrer-when-downgrade",
}
HEADER_MAX_POINTS = 40


def _is_redis_truthy(val: object) -> bool:
    return isinstance(val, (bool, int)) and bool(val)


def _normalize_hostname(host: str) -> str:
    """Normalizes a hostname or IP literal to lowercase ASCII (IDNA Punycode for IDNs)."""
    cleaned = host.strip().strip("[]").rstrip(".").lower()
    if not cleaned:
        return ""
    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        pass
    labels: list[str] = []
    for label in cleaned.split("."):
        if not label or label == "*":
            labels.append(label)
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


async def _safe_validate_url(url: str) -> tuple[str, list[str]]:
    """Wraps app.core.ssrf.validate_url to convert URL/port parsing ValueErrors into AppError(400)."""
    try:
        parsed = urlparse(url)
        _ = parsed.port
    except ValueError as exc:
        raise AppError(400, "invalid_url", f"Malformed URL or invalid port: {exc}") from exc
    return await validate_url(url)


def normalize_url_indicator(raw_url: str) -> str:
    """Normalizes a URL for consistent Redis threat feed storage and lookup."""
    cleaned = raw_url.strip()
    try:
        parsed = urlparse(cleaned)
        port = parsed.port
    except ValueError:
        return cleaned.lower()
    if not parsed.scheme or not parsed.hostname:
        return cleaned.lower()
    scheme = parsed.scheme.lower()
    host = _normalize_hostname(parsed.hostname)
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    host_netloc = f"[{host}]" if ":" in host else host
    netloc = f"{host_netloc}:{port}" if port else host_netloc
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def parse_feed_entries(raw_text: str) -> tuple[set[str], set[str]]:
    """Extracts normalized URLs and hostnames from URLhaus or OpenPhish feed payloads."""
    urls: set[str] = set()
    hosts: set[str] = set()

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        candidate_url: str | None = None
        if line.startswith(("http://", "https://")):
            candidate_url = line
        elif "," in line and ("http://" in line or "https://" in line):
            for part in line.split(","):
                stripped = part.strip().strip('"').strip("'")
                if stripped.startswith(("http://", "https://")):
                    candidate_url = stripped
                    break

        if candidate_url:
            try:
                parsed = urlparse(candidate_url)
                _ = parsed.port
            except ValueError:
                continue
            if not parsed.hostname:
                continue
            norm = normalize_url_indicator(candidate_url)
            urls.add(norm)
            norm_host = _normalize_hostname(parsed.hostname)
            if norm_host:
                hosts.add(norm_host)
        elif " " not in line and "." in line and "/" not in line and ":" not in line:
            norm_host = _normalize_hostname(line)
            if norm_host:
                hosts.add(norm_host)

    return urls, hosts


def _extract_x509_name(name: x509.Name) -> str:
    try:
        cn_attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            val = cn_attrs[0].value
            return val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
    except Exception:
        pass
    return name.rfc4514_string()


def _match_hostname(hostname: str, san_list: list[str], subject_cn: str | None) -> bool:
    """Validates hostname against certificate SANs (or CN fallback) per RFC 6125."""
    target = _normalize_hostname(hostname)
    if not target:
        return False
    candidates = list(san_list) if san_list else ([subject_cn] if subject_cn else [])

    target_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        pass

    for pattern in candidates:
        if not pattern:
            continue
        pat = _normalize_hostname(pattern)
        if not pat:
            continue
        if target_ip is not None:
            try:
                if target_ip == ipaddress.ip_address(pat):
                    return True
            except ValueError:
                pass
        if target == pat:
            return True
        if target_ip is None and pat.startswith("*."):
            suffix = pat[2:]
            if "." in suffix and target.endswith(f".{suffix}"):
                leftmost = target[: -(len(suffix) + 1)]
                if leftmost and "." not in leftmost:
                    return True
    return False


def parse_and_validate_x509_cert(
    cert_data: bytes | x509.Certificate,
    hostname: str,
    protocol: str | None = None,
    cipher: str | None = None,
    chain_trusted: bool = True,
    verification_error: str | None = None,
    now: datetime | None = None,
) -> SSLInfo:
    """Parses an X.509 certificate with cryptography and evaluates its security validity."""
    if isinstance(cert_data, bytes):
        if cert_data.lstrip().startswith(b"-----BEGIN"):
            cert = x509.load_pem_x509_certificate(cert_data)
        else:
            cert = x509.load_der_x509_certificate(cert_data)
    else:
        cert = cert_data

    current_time = now or datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    delta_seconds = (not_after - current_time).total_seconds()
    days_remaining = int(delta_seconds // 86400)
    expired = current_time >= not_after
    not_yet_valid = current_time < not_before

    subject_str = _extract_x509_name(cert.subject)
    issuer_str = _extract_x509_name(cert.issuer)
    self_signed = len(cert.subject) > 0 and cert.issuer == cert.subject
    if self_signed:
        try:
            aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
            ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
            if aki.key_identifier is not None and ski.digest is not None and aki.key_identifier != ski.digest:
                self_signed = False
        except x509.ExtensionNotFound:
            pass

    san_entries: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_val = san_ext.value
        dns_names = san_val.get_values_for_type(x509.DNSName)
        ip_addrs = [str(ip) for ip in san_val.get_values_for_type(x509.IPAddress)]
        san_entries.extend(dns_names)
        san_entries.extend(ip_addrs)
    except x509.ExtensionNotFound:
        pass

    hostname_match = _match_hostname(hostname, san_entries, subject_str)

    pub_key = cert.public_key()
    key_algorithm: str | None = None
    key_size: int | None = None
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_algorithm = "RSA"
        key_size = int(pub_key.key_size)
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_algorithm = "EC"
        key_size = int(pub_key.key_size)
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_algorithm = "DSA"
        key_size = int(pub_key.key_size)
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        key_algorithm = "Ed25519"
        key_size = 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        key_algorithm = "Ed448"
        key_size = 448
    else:
        key_algorithm = type(pub_key).__name__
        raw_size = getattr(pub_key, "key_size", None)
        key_size = int(raw_size) if isinstance(raw_size, int) else None

    sig_hash = (
        cert.signature_hash_algorithm.name.lower()
        if cert.signature_hash_algorithm is not None
        else None
    )

    errors: list[str] = []
    warnings: list[str] = []

    if expired:
        errors.append("Certificate has expired.")
    if not_yet_valid:
        errors.append("Certificate validity period has not started yet.")
    if not hostname_match:
        errors.append(f"Hostname '{hostname}' does not match certificate SAN/CN.")
    if self_signed:
        errors.append("Certificate is self-signed.")
    if not chain_trusted:
        detail = f" ({verification_error})" if verification_error else ""
        errors.append(f"Untrusted certificate chain{detail}.")
    if protocol and protocol in DEPRECATED_TLS_PROTOCOLS:
        errors.append(f"Deprecated TLS protocol version: {protocol}.")
    if sig_hash and sig_hash in WEAK_SIGNATURE_HASHES:
        errors.append(f"Weak certificate signature hash algorithm: {sig_hash}.")
    if key_algorithm in {"RSA", "DSA"} and key_size is not None and key_size < 2048:
        errors.append(f"Weak {key_algorithm} key size ({key_size} bits < 2048 bits).")
    if key_algorithm == "EC" and key_size is not None and key_size < 224:
        errors.append(f"Weak EC key size ({key_size} bits < 224 bits).")

    if not expired and not not_yet_valid:
        if days_remaining < 14:
            warnings.append(f"Certificate expires critically soon ({days_remaining} days remaining).")
        elif days_remaining < 30:
            warnings.append(f"Certificate expires soon ({days_remaining} days remaining).")

    trusted_chain = bool(chain_trusted and not self_signed)
    is_valid = bool(
        not expired
        and not not_yet_valid
        and hostname_match
        and trusted_chain
        and len(errors) == 0
    )

    return SSLInfo(
        enabled=True,
        valid=is_valid,
        trusted_chain=trusted_chain,
        hostname_match=hostname_match,
        expired=expired,
        not_yet_valid=not_yet_valid,
        self_signed=self_signed,
        protocol=protocol,
        cipher=cipher,
        subject=subject_str,
        issuer=issuer_str,
        serial_number=hex(cert.serial_number),
        not_before=not_before,
        not_after=not_after,
        days_remaining=days_remaining,
        san=san_entries,
        signature_algorithm=sig_hash,
        key_algorithm=key_algorithm,
        key_size=key_size,
        errors=errors,
        warnings=warnings,
    )


async def perform_tls_handshake(
    hostname: str,
    ip: str,
    port: int = 443,
    timeout: float = 10.0,
) -> SSLInfo:
    """Connects to the pre-validated IP with SNI and inspects the peer X.509 certificate."""
    sni_hostname = _normalize_hostname(hostname) or hostname

    async def _connect_with_context(ctx: ssl.SSLContext) -> tuple[bytes | None, str | None, str | None]:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host=ip, port=port, ssl=ctx, server_hostname=sni_hostname),
            timeout=timeout,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                return None, None, None
            der_bytes = ssl_obj.getpeercert(binary_form=True)
            proto = ssl_obj.version()
            cipher_tuple = ssl_obj.cipher()
            cipher_name = cipher_tuple[0] if cipher_tuple else None
            return der_bytes, proto, cipher_name
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    verified_ctx = ssl.create_default_context()
    try:
        is_ip = False
        try:
            ipaddress.ip_address(sni_hostname)
            is_ip = True
        except ValueError:
            pass
        if is_ip:
            verified_ctx.check_hostname = False

        der_cert, protocol, cipher = await _connect_with_context(verified_ctx)
        if not der_cert:
            return SSLInfo(
                enabled=False,
                valid=False,
                errors=["Peer did not present an X.509 certificate."],
            )
        return parse_and_validate_x509_cert(
            der_cert,
            hostname=hostname,
            protocol=protocol,
            cipher=cipher,
            chain_trusted=True,
        )
    except ssl.SSLCertVerificationError as verify_exc:
        verification_error = getattr(verify_exc, "verify_message", None) or str(verify_exc)
        unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode = ssl.CERT_NONE
        try:
            unverified_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            der_cert, protocol, cipher = await _connect_with_context(unverified_ctx)
            if der_cert:
                return parse_and_validate_x509_cert(
                    der_cert,
                    hostname=hostname,
                    protocol=protocol,
                    cipher=cipher,
                    chain_trusted=False,
                    verification_error=verification_error,
                )
        except Exception:
            pass
        return SSLInfo(
            enabled=True,
            valid=False,
            trusted_chain=False,
            errors=[f"SSL certificate verification failed: {verification_error}"],
        )
    except Exception as exc:
        return SSLInfo(
            enabled=False,
            valid=False,
            errors=[f"TLS handshake failed: {exc}"],
        )


def _csp_has_permissive_wildcard(csp_lower: str) -> bool:
    """Checks whether default-src or script-src contains an unrestricted wildcard source (*, http://*, https://*, data:)."""
    for clause in re.split(r"[;,]", csp_lower):
        tokens = clause.strip().split()
        if not tokens:
            continue
        directive = tokens[0]
        if directive in {"default-src", "script-src"}:
            for src in tokens[1:]:
                cleaned_src = src.strip()
                if cleaned_src in {"*", "http://*", "https://*", "*://*", "data:"}:
                    return True
    return False


def _csp_has_restrictive_frame_ancestors(csp_val: str | None) -> bool:
    """Checks whether Content-Security-Policy defines a non-wildcard frame-ancestors directive."""
    if not csp_val:
        return False
    found_valid = False
    for clause in re.split(r"[;,]", csp_val.lower()):
        tokens = clause.strip().split()
        if not tokens or tokens[0] != "frame-ancestors":
            continue
        sources = tokens[1:]
        if not sources:
            return False
        if any(s in {"*", "http://*", "https://*", "*://*"} for s in sources):
            return False
        found_valid = True
    return found_valid


def audit_security_headers(raw_headers: dict[str, str] | httpx.Headers) -> HeadersAuditResult:
    """Audits HTTP response headers for OWASP security controls and information leaks."""
    lower_map: dict[str, str] = {}
    for k, v in raw_headers.items():
        key_l = k.lower()
        val_s = str(v).strip()
        if key_l in lower_map and val_s:
            lower_map[key_l] = f"{lower_map[key_l]}, {val_s}"
        else:
            lower_map[key_l] = val_s

    present: list[str] = []
    missing: list[str] = []
    warnings: list[str] = []
    leaked_headers: dict[str, str] = {}
    details: dict[str, HeaderFinding] = {}

    # 1. Strict-Transport-Security (10 pts)
    hsts_val = lower_map.get("strict-transport-security")
    if hsts_val is None:
        missing.append("Strict-Transport-Security")
        details["strict-transport-security"] = HeaderFinding(
            name="Strict-Transport-Security",
            present=False,
            value=None,
            status="fail",
            score_deduction=10,
            recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
        )
    else:
        present.append("Strict-Transport-Security")
        matches = re.findall(r'max-age\s*=\s*"?(\d+)"?', hsts_val, re.IGNORECASE)
        max_age = min(int(m) for m in matches) if matches else -1
        if max_age <= 0:
            warnings.append("Strict-Transport-Security has max-age=0 or invalid max-age.")
            details["strict-transport-security"] = HeaderFinding(
                name="Strict-Transport-Security",
                present=True,
                value=hsts_val,
                status="fail",
                score_deduction=10,
                recommendation="Set HSTS max-age to at least 31536000 seconds (1 year).",
            )
        elif max_age < 31536000:
            warnings.append(f"Strict-Transport-Security max-age ({max_age}) is less than 1 year (31536000).")
            details["strict-transport-security"] = HeaderFinding(
                name="Strict-Transport-Security",
                present=True,
                value=hsts_val,
                status="warn",
                score_deduction=5,
                recommendation="Increase HSTS max-age to at least 31536000 seconds and consider includeSubDomains.",
            )
        else:
            details["strict-transport-security"] = HeaderFinding(
                name="Strict-Transport-Security",
                present=True,
                value=hsts_val,
                status="pass",
                score_deduction=0,
            )

    # 2. Content-Security-Policy (10 pts)
    csp_val = lower_map.get("content-security-policy")
    if csp_val is None:
        missing.append("Content-Security-Policy")
        details["content-security-policy"] = HeaderFinding(
            name="Content-Security-Policy",
            present=False,
            value=None,
            status="fail",
            score_deduction=10,
            recommendation="Define a restrictive Content-Security-Policy header without 'unsafe-inline' or 'unsafe-eval'.",
        )
    else:
        present.append("Content-Security-Policy")
        csp_lower = csp_val.lower()
        has_unsafe = "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower
        has_wildcard_src = _csp_has_permissive_wildcard(csp_lower)
        if has_unsafe or has_wildcard_src:
            warnings.append("Content-Security-Policy contains permissive directives ('unsafe-inline', 'unsafe-eval', or '*').")
            details["content-security-policy"] = HeaderFinding(
                name="Content-Security-Policy",
                present=True,
                value=csp_val,
                status="warn",
                score_deduction=5,
                recommendation="Remove 'unsafe-inline', 'unsafe-eval', and wildcard sources from Content-Security-Policy.",
            )
        else:
            details["content-security-policy"] = HeaderFinding(
                name="Content-Security-Policy",
                present=True,
                value=csp_val,
                status="pass",
                score_deduction=0,
            )

    # 3. X-Content-Type-Options (6 pts)
    xcto_val = lower_map.get("x-content-type-options")
    if xcto_val is None:
        missing.append("X-Content-Type-Options")
        details["x-content-type-options"] = HeaderFinding(
            name="X-Content-Type-Options",
            present=False,
            value=None,
            status="fail",
            score_deduction=6,
            recommendation="Add 'X-Content-Type-Options: nosniff'.",
        )
    else:
        present.append("X-Content-Type-Options")
        xcto_tokens = [t.strip().lower() for t in xcto_val.split(",") if t.strip()]
        if xcto_tokens and all(t == "nosniff" for t in xcto_tokens):
            details["x-content-type-options"] = HeaderFinding(
                name="X-Content-Type-Options",
                present=True,
                value=xcto_val,
                status="pass",
                score_deduction=0,
            )
        else:
            warnings.append(f"X-Content-Type-Options has unexpected value '{xcto_val}'.")
            details["x-content-type-options"] = HeaderFinding(
                name="X-Content-Type-Options",
                present=True,
                value=xcto_val,
                status="warn",
                score_deduction=3,
                recommendation="Set X-Content-Type-Options strictly to 'nosniff'.",
            )

    # 4. X-Frame-Options (6 pts)
    xfo_val = lower_map.get("x-frame-options")
    csp_has_frame_ancestors = _csp_has_restrictive_frame_ancestors(csp_val)
    if xfo_val is None:
        if csp_has_frame_ancestors:
            present.append("X-Frame-Options")
            details["x-frame-options"] = HeaderFinding(
                name="X-Frame-Options",
                present=True,
                value="CSP frame-ancestors",
                status="pass",
                score_deduction=0,
            )
        else:
            missing.append("X-Frame-Options")
            details["x-frame-options"] = HeaderFinding(
                name="X-Frame-Options",
                present=False,
                value=None,
                status="fail",
                score_deduction=6,
                recommendation="Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') or CSP 'frame-ancestors'.",
            )
    else:
        present.append("X-Frame-Options")
        xfo_tokens = {t.strip().upper() for t in xfo_val.split(",") if t.strip()}
        if len(xfo_tokens) == 1 and next(iter(xfo_tokens)) in {"DENY", "SAMEORIGIN"}:
            details["x-frame-options"] = HeaderFinding(
                name="X-Frame-Options",
                present=True,
                value=xfo_val,
                status="pass",
                score_deduction=0,
            )
        else:
            warnings.append(f"X-Frame-Options uses weak or legacy directive '{xfo_val}'.")
            details["x-frame-options"] = HeaderFinding(
                name="X-Frame-Options",
                present=True,
                value=xfo_val,
                status="warn",
                score_deduction=3,
                recommendation="Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options.",
            )

    # 5. Referrer-Policy (4 pts)
    ref_val = lower_map.get("referrer-policy")
    if ref_val is None:
        missing.append("Referrer-Policy")
        details["referrer-policy"] = HeaderFinding(
            name="Referrer-Policy",
            present=False,
            value=None,
            status="fail",
            score_deduction=4,
            recommendation="Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        )
    else:
        present.append("Referrer-Policy")
        tokens = [t.strip().lower() for t in ref_val.split(",") if t.strip()]
        effective_policy = tokens[-1] if tokens else ""
        if effective_policy in SAFE_REFERRER_POLICIES and "unsafe-url" not in tokens:
            details["referrer-policy"] = HeaderFinding(
                name="Referrer-Policy",
                present=True,
                value=ref_val,
                status="pass",
                score_deduction=0,
            )
        else:
            warnings.append(f"Referrer-Policy '{ref_val}' may leak sensitive URLs cross-origin.")
            details["referrer-policy"] = HeaderFinding(
                name="Referrer-Policy",
                present=True,
                value=ref_val,
                status="warn",
                score_deduction=2,
                recommendation="Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
            )

    # 6. Permissions-Policy (4 pts)
    perm_val = lower_map.get("permissions-policy")
    if perm_val is None:
        missing.append("Permissions-Policy")
        details["permissions-policy"] = HeaderFinding(
            name="Permissions-Policy",
            present=False,
            value=None,
            status="fail",
            score_deduction=4,
            recommendation="Add 'Permissions-Policy' restricting sensitive browser features (camera, microphone, geolocation).",
        )
    else:
        present.append("Permissions-Policy")
        if "=*" in perm_val.replace(" ", ""):
            warnings.append("Permissions-Policy grants wildcard access to one or more features.")
            details["permissions-policy"] = HeaderFinding(
                name="Permissions-Policy",
                present=True,
                value=perm_val,
                status="warn",
                score_deduction=2,
                recommendation="Restrict sensitive features in Permissions-Policy instead of allowing '*'.",
            )
        else:
            details["permissions-policy"] = HeaderFinding(
                name="Permissions-Policy",
                present=True,
                value=perm_val,
                status="pass",
                score_deduction=0,
            )

    # Check information disclosure headers
    info_leak_deduction = 0
    for leak_key, canonical in (
        ("x-powered-by", "X-Powered-By"),
        ("x-aspnet-version", "X-AspNet-Version"),
        ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
    ):
        if leak_key in lower_map:
            leaked_headers[canonical] = lower_map[leak_key]
            warnings.append(f"Information disclosure header '{canonical}: {lower_map[leak_key]}' is exposed.")
            info_leak_deduction = min(3, info_leak_deduction + 3)

    server_val = lower_map.get("server")
    if server_val and re.search(r"/\d", server_val):
        leaked_headers["Server"] = server_val
        warnings.append(f"Server header exposes version information: '{server_val}'.")
        info_leak_deduction += 2

    total_header_deductions = sum(item.score_deduction for item in details.values())
    earned_points = max(0, HEADER_MAX_POINTS - total_header_deductions)
    sub_score = max(0, int(round((earned_points / HEADER_MAX_POINTS) * 100)) - info_leak_deduction)

    return HeadersAuditResult(
        score=sub_score,
        present=present,
        missing=missing,
        warnings=warnings,
        leaked_headers=leaked_headers,
        details=details,
    )


def score_to_grade(score: int) -> SecurityGrade:
    """Maps a numeric security score (0-100) to a security letter grade."""
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def calculate_security_score(
    ssl_info: SSLInfo,
    headers_result: HeadersAuditResult,
    threat_intel: ThreatIntelResult | None = None,
) -> tuple[int, SecurityGrade]:
    """Calculates the composite 0-100 security score and grade from SSL, headers, and threat intel."""
    score = 100

    # 1. TLS / SSL deductions
    if not ssl_info.enabled or not ssl_info.valid:
        score -= 45
    else:
        if ssl_info.days_remaining is not None:
            if ssl_info.days_remaining < 7:
                score -= 15
            elif ssl_info.days_remaining < 14:
                score -= 10
            elif ssl_info.days_remaining < 30:
                score -= 5

    # 2. HTTP Security Headers deductions (up to 40 pts)
    header_deductions = sum(f.score_deduction for f in headers_result.details.values())
    score -= min(HEADER_MAX_POINTS, header_deductions)

    # 3. Information disclosure penalties (up to 5 pts)
    if any(k in headers_result.leaked_headers for k in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")):
        score -= 3
    if "Server" in headers_result.leaked_headers:
        score -= 2

    # 4. Threat intelligence penalty (URLhaus / OpenPhish)
    if threat_intel is not None and (
        threat_intel.is_malicious or threat_intel.urlhaus_listed or threat_intel.openphish_listed
    ):
        if threat_intel.urlhaus_listed:
            score -= 75
        if threat_intel.openphish_listed:
            score -= 75
        score = min(score, 15)

    final_score = max(0, min(100, int(score)))
    return final_score, score_to_grade(final_score)


class SecurityAuditService:
    """Core service executing SSRF-safe TLS verification, header audits, and threat feed checks."""

    def __init__(
        self,
        redis_client: redis.Redis,
        http_client: httpx.AsyncClient | None = None,
        urlhaus_url: str = URLHAUS_FEED_URL,
        openphish_url: str = OPENPHISH_FEED_URL,
    ) -> None:
        self.redis = redis_client
        self.http_client = http_client
        self.urlhaus_url = urlhaus_url
        self.openphish_url = openphish_url

    async def _store_set_in_redis(self, key: str, items: set[str]) -> None:
        if not items:
            await self.redis.delete(key)
            return
        ordered = list(items)
        if hasattr(self.redis, "rename"):
            tmp_key = f"{key}:tmp:{uuid.uuid4().hex}"
            try:
                for idx in range(0, len(ordered), REDIS_BATCH_SIZE):
                    batch = ordered[idx : idx + REDIS_BATCH_SIZE]
                    await self.redis.sadd(tmp_key, *batch)
                await self.redis.expire(tmp_key, FEED_TTL_SECONDS)
                await self.redis.rename(tmp_key, key)
            except Exception:
                await self.redis.delete(tmp_key)
                raise
        else:
            await self.redis.delete(key)
            for idx in range(0, len(ordered), REDIS_BATCH_SIZE):
                batch = ordered[idx : idx + REDIS_BATCH_SIZE]
                await self.redis.sadd(key, *batch)
            await self.redis.expire(key, FEED_TTL_SECONDS)

    async def sync_threat_feeds(self, timeout: float = 15.0) -> FeedSyncResponse:
        """Asynchronously fetches URLhaus and OpenPhish feeds and caches indicators in Redis."""
        errors: list[str] = []
        urlhaus_count = 0
        openphish_count = 0

        async def _fetch_feed(client: httpx.AsyncClient, name: str, feed_url: str) -> str | None:
            try:
                resp = await client.get(feed_url)
                resp.raise_for_status()
                return resp.text
            except Exception as exc:
                errors.append(f"{name} sync failed: {exc}")
                return None

        if self.http_client is not None:
            uh_text, op_text = await asyncio.gather(
                _fetch_feed(self.http_client, "urlhaus", self.urlhaus_url),
                _fetch_feed(self.http_client, "openphish", self.openphish_url),
            )
        else:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                uh_text, op_text = await asyncio.gather(
                    _fetch_feed(client, "urlhaus", self.urlhaus_url),
                    _fetch_feed(client, "openphish", self.openphish_url),
                )

        try:
            if uh_text is not None:
                uh_urls, uh_hosts = parse_feed_entries(uh_text)
                urlhaus_count = len(uh_urls)
                await self._store_set_in_redis(REDIS_KEY_URLHAUS_URLS, uh_urls)
                await self._store_set_in_redis(REDIS_KEY_URLHAUS_HOSTS, uh_hosts)

            if op_text is not None:
                op_urls, op_hosts = parse_feed_entries(op_text)
                openphish_count = len(op_urls)
                await self._store_set_in_redis(REDIS_KEY_OPENPHISH_URLS, op_urls)
                await self._store_set_in_redis(REDIS_KEY_OPENPHISH_HOSTS, op_hosts)

            synced_at = datetime.now(timezone.utc).isoformat()
            if uh_text is not None or op_text is not None:
                await self.redis.set(REDIS_KEY_FEEDS_LAST_SYNC, synced_at, ex=FEED_TTL_SECONDS)
        except Exception as exc:
            errors.append(f"Redis storage failed: {exc}")
            synced_at = datetime.now(timezone.utc).isoformat()

        return FeedSyncResponse(
            synced=len(errors) == 0,
            urlhaus_count=urlhaus_count,
            openphish_count=openphish_count,
            synced_at=synced_at,
            errors=errors,
        )

    async def check_threat_feeds(self, url: str, hostname: str) -> ThreatIntelResult:
        """Checks Redis threat intelligence sets for URLhaus and OpenPhish matches."""
        norm_url = normalize_url_indicator(url)
        raw_url = url.strip()
        norm_host = _normalize_hostname(hostname)

        try:
            uh_url_hit, uh_host_hit, op_url_hit, op_host_hit, last_sync = await asyncio.gather(
                self.redis.sismember(REDIS_KEY_URLHAUS_URLS, norm_url),
                self.redis.sismember(REDIS_KEY_URLHAUS_HOSTS, norm_host),
                self.redis.sismember(REDIS_KEY_OPENPHISH_URLS, norm_url),
                self.redis.sismember(REDIS_KEY_OPENPHISH_HOSTS, norm_host),
                self.redis.get(REDIS_KEY_FEEDS_LAST_SYNC),
            )
            if not _is_redis_truthy(uh_url_hit) and raw_url != norm_url:
                uh_url_hit = await self.redis.sismember(REDIS_KEY_URLHAUS_URLS, raw_url)
            if not _is_redis_truthy(op_url_hit) and raw_url != norm_url:
                op_url_hit = await self.redis.sismember(REDIS_KEY_OPENPHISH_URLS, raw_url)
        except Exception:
            return ThreatIntelResult()

        urlhaus_listed = _is_redis_truthy(uh_url_hit) or _is_redis_truthy(uh_host_hit)
        openphish_listed = _is_redis_truthy(op_url_hit) or _is_redis_truthy(op_host_hit)

        matched_feeds: list[str] = []
        matched_indicators: list[str] = []

        if urlhaus_listed:
            matched_feeds.append("urlhaus")
            matched_indicators.append(norm_url if _is_redis_truthy(uh_url_hit) else norm_host)
        if openphish_listed:
            matched_feeds.append("openphish")
            indicator = norm_url if _is_redis_truthy(op_url_hit) else norm_host
            if indicator not in matched_indicators:
                matched_indicators.append(indicator)

        if isinstance(last_sync, bytes):
            last_sync_str: str | None = last_sync.decode("utf-8", errors="replace")
        elif isinstance(last_sync, str):
            last_sync_str = last_sync
        else:
            last_sync_str = None

        return ThreatIntelResult(
            is_malicious=bool(urlhaus_listed or openphish_listed),
            urlhaus_listed=urlhaus_listed,
            openphish_listed=openphish_listed,
            matched_feeds=matched_feeds,
            matched_indicators=matched_indicators,
            feeds_last_sync=last_sync_str,
        )

    async def check_tls(
        self,
        hostname: str,
        ip: str,
        port: int = 443,
        timeout: float = 10.0,
    ) -> SSLInfo:
        """Executes TLS handshake and X.509 certificate inspection."""
        return await perform_tls_handshake(hostname=hostname, ip=ip, port=port, timeout=timeout)

    @staticmethod
    def _build_pinned_target(url: str, ip: str) -> tuple[str, str, str]:
        """Rewrites URL to connect directly to a pre-validated public IP (preventing DNS rebinding)."""
        parsed = urlparse(url)
        raw_hostname = parsed.hostname or ip
        ascii_hostname = _normalize_hostname(raw_hostname) or raw_hostname
        ip_host = f"[{ip}]" if ":" in ip and not ip.startswith("[") else ip
        netloc = f"{ip_host}:{parsed.port}" if parsed.port else ip_host
        host_for_header = (
            f"[{ascii_hostname}]"
            if ":" in ascii_hostname and not ascii_hostname.startswith("[")
            else ascii_hostname
        )
        host_header = f"{host_for_header}:{parsed.port}" if parsed.port else host_for_header
        pinned_url = parsed._replace(netloc=netloc).geturl()
        return pinned_url, host_header, ascii_hostname

    async def fetch_http_response(
        self,
        initial_url: str,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        initial_ips: list[str] | None = None,
    ) -> tuple[str, list[str], int | None, dict[str, str]]:
        """Fetches HTTP headers using pre-validated public IPs while checking every redirect hop against SSRF."""
        current_url = initial_url
        current_ips: list[str] = list(initial_ips) if initial_ips else []

        async def _do_fetch(client: httpx.AsyncClient) -> tuple[str, list[str], int | None, dict[str, str]]:
            nonlocal current_url, current_ips
            if not current_ips:
                current_url, current_ips = await _safe_validate_url(current_url)
            for _ in range(MAX_REDIRECTS + 1):
                pinned_url, host_header, sni_host = self._build_pinned_target(current_url, current_ips[0])
                resp = await client.get(
                    pinned_url,
                    headers={"Host": host_header},
                    extensions={"sni_hostname": sni_host},
                )
                if (
                    follow_redirects
                    and resp.status_code in {301, 302, 303, 307, 308}
                    and "location" in resp.headers
                ):
                    next_url = urljoin(current_url, resp.headers["location"].strip())
                    next_url, next_ips = await _safe_validate_url(next_url)
                    current_url, current_ips = next_url, next_ips
                    continue
                return current_url, current_ips, int(resp.status_code), dict(resp.headers)
            raise AppError(400, "too_many_redirects", f"Exceeded maximum of {MAX_REDIRECTS} redirects.")

        try:
            if self.http_client is not None:
                return await _do_fetch(self.http_client)
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
                return await _do_fetch(client)
        except AppError:
            raise
        except Exception:
            if not current_ips:
                _, current_ips = await _safe_validate_url(current_url)
            return current_url, current_ips, None, {}

    async def audit(self, request: AuditRequest) -> AuditResponse:
        """Performs full security audit on a URL: SSRF check, TLS/SSL, HTTP headers, and threat feeds."""
        validated_url, resolved_ips = await _safe_validate_url(request.url)

        if request.sync_feeds:
            await self.sync_threat_feeds(timeout=request.timeout)

        final_url, final_ips, http_status, raw_headers = await self.fetch_http_response(
            initial_url=validated_url,
            timeout=request.timeout,
            follow_redirects=request.follow_redirects,
            initial_ips=resolved_ips,
        )

        active_url = final_url or validated_url
        active_ips = final_ips or resolved_ips
        parsed = urlparse(active_url)
        hostname = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)

        if scheme == "https":
            ssl_Task = self.check_tls(
                hostname=hostname,
                ip=active_ips[0],
                port=port,
                timeout=request.timeout,
            )
        else:
            async def _plain_http_ssl() -> SSLInfo:
                return SSLInfo(
                    enabled=False,
                    valid=False,
                    errors=["Target uses unencrypted HTTP (TLS/SSL not enabled)."],
                )
            ssl_Task = _plain_http_ssl()

        ssl_info, threat_intel = await asyncio.gather(
            ssl_Task,
            self.check_threat_feeds(url=active_url, hostname=hostname),
        )

        # If final_url redirected to a different URL than initial validated_url, also check initial URL in threat feeds
        if active_url != validated_url and not threat_intel.is_malicious:
            initial_host = (urlparse(validated_url).hostname or "").lower()
            initial_threat = await self.check_threat_feeds(url=validated_url, hostname=initial_host)
            if initial_threat.is_malicious:
                threat_intel = initial_threat

        headers_result = audit_security_headers(raw_headers)
        score, grade = calculate_security_score(
            ssl_info=ssl_info,
            headers_result=headers_result,
            threat_intel=threat_intel,
        )

        recommendations: list[str] = []
        if threat_intel.is_malicious:
            feeds_str = ", ".join(threat_intel.matched_feeds)
            recommendations.append(
                f"CRITICAL: Target is listed in threat intelligence feeds ({feeds_str}). Block access immediately."
            )
        for err in ssl_info.errors:
            recommendations.append(f"SSL/TLS Error: {err}")
        for warn in ssl_info.warnings:
            recommendations.append(f"SSL/TLS Warning: {warn}")
        for finding in headers_result.details.values():
            if finding.recommendation:
                recommendations.append(finding.recommendation)
        for leaked_name in headers_result.leaked_headers:
            recommendations.append(f"Remove or obfuscate the '{leaked_name}' header to prevent information disclosure.")

        return AuditResponse(
            url=validated_url,
            final_url=active_url,
            hostname=hostname,
            resolved_ips=active_ips,
            http_status=http_status,
            score=score,
            grade=grade,
            ssl=ssl_info,
            headers=headers_result,
            threat_intel=threat_intel,
            recommendations=recommendations,
            audited_at=datetime.now(timezone.utc),
        )
