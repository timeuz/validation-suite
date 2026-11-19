from typing import Literal

from pydantic import BaseModel, Field, field_validator

SupportedEncoding = Literal["cl100k_base", "o200k_base", "p50k_base", "r50k_base"]
UrlOutputFormat = Literal["markdown", "txt"]


class UrlExtractRequest(BaseModel):
    """Input payload for extracting content and token counts from a public URL."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Public HTTP(S) URL to extract content from.",
    )
    output_format: UrlOutputFormat = Field(
        default="markdown",
        description="Extracted output format.",
    )
    include_links: bool = Field(
        default=False,
        description="Preserve hyperlinks in extracted output.",
    )
    include_tables: bool = Field(
        default=True,
        description="Include HTML tables in extracted output.",
    )
    include_comments: bool = Field(
        default=False,
        description="Include comment sections when extracting HTML.",
    )
    favor_precision: bool = Field(
        default=False,
        description="Prefer lower noise over recall during extraction.",
    )
    favor_recall: bool = Field(
        default=False,
        description="Prefer higher recall when main content is sparse.",
    )
    encoding: SupportedEncoding = Field(
        default="cl100k_base",
        description="tiktoken encoding used to count tokens.",
    )
    use_cache: bool = Field(
        default=True,
        description="Whether to read from Redis cache before fetching the URL.",
    )

    @field_validator("url")
    @classmethod
    def validate_url_not_blank(cls, value: str) -> str:
        """Strip whitespace and reject blank URL strings."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("URL must not be blank.")
        return cleaned


class PdfExtractOptions(BaseModel):
    """Form options controlling PDF token counting."""

    encoding: SupportedEncoding = Field(
        default="cl100k_base",
        description="tiktoken encoding used to count tokens.",
    )


class PdfUploadMetadata(BaseModel):
    """Validated metadata for an uploaded PDF file."""

    filename: str = Field(..., min_length=1, max_length=255)
    content_type: str | None = None
    size_bytes: int = Field(..., ge=1)


class WebMetadata(BaseModel):
    """Optional bibliographic metadata extracted from a web page."""

    title: str | None = None
    author: str | None = None
    date: str | None = None
    sitename: str | None = None
    language: str | None = None
    description: str | None = None


class UrlExtractResponse(BaseModel):
    """Extracted web content, metadata, and token count response."""

    url: str
    final_url: str
    content: str
    output_format: UrlOutputFormat
    char_count: int = Field(..., ge=0)
    token_count: int = Field(..., ge=0)
    encoding: SupportedEncoding
    cached: bool = False
    metadata: WebMetadata = Field(default_factory=WebMetadata)


class PdfMetadata(BaseModel):
    """Document metadata embedded in a PDF file."""

    title: str | None = None
    author: str | None = None
    subject: str | None = None
    creator: str | None = None
    producer: str | None = None


class PdfExtractResponse(BaseModel):
    """Extracted PDF Markdown content, metadata, and token count response."""

    filename: str
    content: str
    output_format: Literal["markdown"] = "markdown"
    page_count: int = Field(..., ge=1, le=50)
    size_bytes: int = Field(..., ge=1)
    char_count: int = Field(..., ge=0)
    token_count: int = Field(..., ge=0)
    encoding: SupportedEncoding
    metadata: PdfMetadata = Field(default_factory=PdfMetadata)
