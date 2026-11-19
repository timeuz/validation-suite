import re
from typing import Literal

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, Field, field_validator

_LOCAL_PART_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_email_syntax_str(value: str) -> str:
    """Validação sintática estrita de endereço de e-mail (RFC 5321/5322 + IDNA 2008 / UTS #46)."""
    if not isinstance(value, str):
        raise ValueError("Email must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Email cannot be empty.")
    if len(cleaned) > 254:
        raise ValueError("Email exceeds maximum length of 254 characters.")
    if any(ord(ch) <= 32 or ord(ch) == 127 or ch.isspace() for ch in cleaned):
        raise ValueError("Email contains invalid whitespace or control characters.")
    if cleaned.count("@") != 1:
        raise ValueError("Email must contain exactly one '@' symbol.")

    local_part, domain_part = cleaned.split("@", 1)
    if not local_part or len(local_part) > 64:
        raise ValueError("Email local part must be between 1 and 64 characters.")
    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        raise ValueError("Email local part has invalid dot placement.")
    if not all(_LOCAL_PART_RE.match(ch) or (ord(ch) > 127 and ch.isalnum()) for ch in local_part):
        raise ValueError("Email local part contains invalid characters.")

    if not domain_part or len(domain_part) > 253 or "." not in domain_part:
        raise ValueError("Email domain must be between 1 and 253 characters and contain a dot.")
    if domain_part.startswith(".") or domain_part.endswith(".") or ".." in domain_part:
        raise ValueError("Email domain has invalid dot placement.")

    try:
        validated = validate_email(cleaned, check_deliverability=False, strict=True)
    except EmailNotValidError as exc:
        raise ValueError(f"Email syntax is invalid: {exc}") from exc

    ascii_domain = (validated.ascii_domain or "").lower()
    if not ascii_domain or len(ascii_domain) > 253 or "." not in ascii_domain:
        raise ValueError("Email domain must contain at least one dot and a valid TLD.")

    labels = ascii_domain.split(".")
    if any(not _DOMAIN_LABEL_RE.match(label) for label in labels):
        raise ValueError("Email domain contains invalid domain labels.")

    tld = labels[-1]
    if len(tld) < 2 or tld.isdigit():
        raise ValueError("Email domain top-level domain (TLD) is invalid.")

    return f"{validated.local_part}@{domain_part.lower()}"


class EmailVerifyRequest(BaseModel):
    email: str = Field(..., description="Endereço de e-mail a ser verificado.")

    @field_validator("email", mode="before")
    @classmethod
    def _validate_syntax(cls, v: object) -> str:
        if not isinstance(v, str):
            raise ValueError("Email must be a valid string.")
        return validate_email_syntax_str(v)


class DomainReputation(BaseModel):
    domain: str
    has_mx: bool = False
    mx_records: list[str] = Field(default_factory=list)
    has_spf: bool = False
    spf_record: str | None = None
    has_dmarc: bool = False
    dmarc_record: str | None = None
    is_disposable: bool = False
    reputation_score: int = Field(default=0, ge=0, le=100)
    reputation_status: Literal["high", "medium", "low", "blocked"] = "low"


class EmailVerifyResponse(BaseModel):
    email: str
    local_part: str
    domain: str
    is_valid: bool
    syntax_valid: bool
    is_disposable: bool
    has_mx: bool
    mx_records: list[str] = Field(default_factory=list)
    has_spf: bool
    spf_record: str | None = None
    has_dmarc: bool
    dmarc_record: str | None = None
    did_you_mean: str | None = None
    reputation_score: int = Field(default=0, ge=0, le=100)
    reputation_status: Literal["high", "medium", "low", "blocked", "invalid"] = "low"
    cached: bool = False

