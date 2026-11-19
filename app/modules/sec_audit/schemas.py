from datetime import datetime
from typing import Literal
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
)

SecurityGrade = Literal["A+", "A", "B", "C", "D", "F"]
HeaderStatus = Literal["pass", "warn", "fail"]


class AuditRequest(BaseModel):
    """Strict input payload for URL security auditing."""

    model_config = ConfigDict(extra="forbid", strict=True)

    url: StrictStr = Field(
        ...,
        min_length=4,
        max_length=2048,
        description="Target HTTP or HTTPS URL to audit.",
    )
    timeout: float = Field(
        default=10.0,
        ge=1.0,
        le=30.0,
        description="Network timeout in seconds for TLS and HTTP probes.",
    )
    follow_redirects: StrictBool = Field(
        default=True,
        description="Whether to follow HTTP redirects (each hop is validated against SSRF).",
    )
    sync_feeds: StrictBool = Field(
        default=False,
        description="Whether to synchronize URLhaus and OpenPhish feeds into Redis before auditing.",
    )

    @field_validator("url")
    @classmethod
    def validate_url_syntax(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or len(cleaned) < 4:
            raise ValueError("URL must not be empty.")
        if any(ch.isspace() or ord(ch) < 32 for ch in cleaned):
            raise ValueError("URL must not contain whitespace or control characters.")
        try:
            parsed = urlparse(cleaned)
            _ = parsed.port
        except ValueError as exc:
            raise ValueError(f"Malformed URL or invalid port: {exc}") from exc
        if not parsed.scheme or "://" not in cleaned or not parsed.hostname:
            raise ValueError("URL must include a valid scheme and hostname.")
        return cleaned


class SSLInfo(BaseModel):
    """TLS/SSL handshake and X.509 certificate audit report."""

    model_config = ConfigDict(extra="forbid", strict=True)

    enabled: StrictBool = Field(..., description="Whether TLS/SSL is enabled on the target.")
    valid: StrictBool = Field(
        ...,
        description="Whether the certificate chain, validity dates, hostname, and TLS parameters are valid.",
    )
    trusted_chain: StrictBool = Field(
        default=False,
        description="Whether the certificate chain is trusted by the CA store.",
    )
    hostname_match: StrictBool = Field(
        default=False,
        description="Whether the target hostname matches the certificate SAN/CN.",
    )
    expired: StrictBool = Field(
        default=False,
        description="Whether the X.509 certificate has expired.",
    )
    not_yet_valid: StrictBool = Field(
        default=False,
        description="Whether the X.509 certificate validity period has not started yet.",
    )
    self_signed: StrictBool = Field(
        default=False,
        description="Whether the certificate is self-signed.",
    )
    protocol: StrictStr | None = Field(
        default=None,
        description="Negotiated TLS protocol version (e.g., TLSv1.3).",
    )
    cipher: StrictStr | None = Field(
        default=None,
        description="Negotiated TLS cipher suite.",
    )
    subject: StrictStr | None = Field(
        default=None,
        description="Certificate subject Common Name or RFC4514 string.",
    )
    issuer: StrictStr | None = Field(
        default=None,
        description="Certificate issuer Common Name or RFC4514 string.",
    )
    serial_number: StrictStr | None = Field(
        default=None,
        description="Certificate serial number in hexadecimal.",
    )
    not_before: datetime | None = Field(
        default=None,
        description="Certificate validity start timestamp (UTC).",
    )
    not_after: datetime | None = Field(
        default=None,
        description="Certificate expiration timestamp (UTC).",
    )
    days_remaining: StrictInt | None = Field(
        default=None,
        description="Remaining days until certificate expiration.",
    )
    san: list[StrictStr] = Field(
        default_factory=list,
        description="Subject Alternative Names (DNS names and IP addresses).",
    )
    signature_algorithm: StrictStr | None = Field(
        default=None,
        description="Certificate signature hash algorithm.",
    )
    key_algorithm: StrictStr | None = Field(
        default=None,
        description="Public key algorithm (RSA, EC, Ed25519, etc.).",
    )
    key_size: StrictInt | None = Field(
        default=None,
        description="Public key size in bits.",
    )
    errors: list[StrictStr] = Field(
        default_factory=list,
        description="Critical TLS/SSL validation errors.",
    )
    warnings: list[StrictStr] = Field(
        default_factory=list,
        description="Non-fatal TLS/SSL warnings.",
    )


class HeaderFinding(BaseModel):
    """Audit result for an individual HTTP security header."""

    model_config = ConfigDict(extra="forbid", strict=True)

    name: StrictStr = Field(..., description="Canonical HTTP security header name.")
    present: StrictBool = Field(..., description="Whether the header was present in the response.")
    value: StrictStr | None = Field(default=None, description="Raw header value if present.")
    status: HeaderStatus = Field(..., description="Audit status: pass, warn, or fail.")
    score_deduction: StrictInt = Field(
        default=0,
        ge=0,
        le=100,
        description="Points deducted for missing or weak header configuration.",
    )
    recommendation: StrictStr | None = Field(
        default=None,
        description="Remediation guidance if status is warn or fail.",
    )


class HeadersAuditResult(BaseModel):
    """Aggregated HTTP security headers audit report."""

    model_config = ConfigDict(extra="forbid", strict=True)

    score: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Security headers sub-score (0 to 100).",
    )
    present: list[StrictStr] = Field(
        default_factory=list,
        description="Canonical names of present security headers.",
    )
    missing: list[StrictStr] = Field(
        default_factory=list,
        description="Canonical names of missing security headers.",
    )
    warnings: list[StrictStr] = Field(
        default_factory=list,
        description="Warnings about weak directives or information-disclosing headers.",
    )
    leaked_headers: dict[StrictStr, StrictStr] = Field(
        default_factory=dict,
        description="Information disclosure headers detected (e.g., X-Powered-By, verbose Server).",
    )
    details: dict[StrictStr, HeaderFinding] = Field(
        default_factory=dict,
        description="Detailed evaluation keyed by lowercase header name.",
    )


class ThreatIntelResult(BaseModel):
    """Threat intelligence feed lookup report (URLhaus & OpenPhish)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    is_malicious: StrictBool = Field(
        default=False,
        description="True if the URL or hostname is listed in URLhaus or OpenPhish.",
    )
    urlhaus_listed: StrictBool = Field(
        default=False,
        description="True if matched in the URLhaus feed.",
    )
    openphish_listed: StrictBool = Field(
        default=False,
        description="True if matched in the OpenPhish feed.",
    )
    matched_feeds: list[StrictStr] = Field(
        default_factory=list,
        description="Threat intelligence feeds that flagged the target.",
    )
    matched_indicators: list[StrictStr] = Field(
        default_factory=list,
        description="Matched URL or hostname indicators.",
    )
    feeds_last_sync: StrictStr | None = Field(
        default=None,
        description="ISO-8601 timestamp of last feed synchronization in Redis.",
    )


class FeedSyncResponse(BaseModel):
    """Result of asynchronous threat feed synchronization into Redis."""

    model_config = ConfigDict(extra="forbid", strict=True)

    synced: StrictBool = Field(..., description="Whether both feeds synchronized without errors.")
    urlhaus_count: StrictInt = Field(
        default=0,
        ge=0,
        description="Number of URLs synchronized from URLhaus.",
    )
    openphish_count: StrictInt = Field(
        default=0,
        ge=0,
        description="Number of URLs synchronized from OpenPhish.",
    )
    synced_at: StrictStr = Field(..., description="UTC ISO-8601 synchronization timestamp.")
    errors: list[StrictStr] = Field(
        default_factory=list,
        description="Errors encountered during feed synchronization.",
    )


class AuditResponse(BaseModel):
    """Complete security audit response payload."""

    model_config = ConfigDict(extra="forbid", strict=True)

    url: StrictStr = Field(..., description="Original audited URL.")
    final_url: StrictStr = Field(..., description="Final URL after redirects.")
    hostname: StrictStr = Field(..., description="Audited target hostname.")
    resolved_ips: list[StrictStr] = Field(
        ...,
        min_length=1,
        description="Validated public IP addresses resolved for the target host.",
    )
    http_status: StrictInt | None = Field(
        default=None,
        description="HTTP status code returned by the target.",
    )
    score: StrictInt = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated overall security score (0-100).",
    )
    grade: SecurityGrade = Field(
        ...,
        description="Calculated security grade (A+, A, B, C, D, F).",
    )
    ssl: SSLInfo = Field(..., description="TLS/SSL handshake and certificate analysis.")
    headers: HeadersAuditResult = Field(..., description="HTTP security headers analysis.")
    threat_intel: ThreatIntelResult = Field(
        ...,
        description="Threat intelligence check against URLhaus and OpenPhish.",
    )
    recommendations: list[StrictStr] = Field(
        default_factory=list,
        description="Actionable security remediation recommendations.",
    )
    audited_at: datetime = Field(..., description="UTC timestamp of the audit.")
