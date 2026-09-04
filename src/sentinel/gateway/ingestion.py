"""Gateway ingestion, document extraction, normalization, and provenance binding."""

import io
import uuid
from pydantic import BaseModel, ConfigDict, Field
from pypdf import PdfReader

from sentinel.hashing import compute_artifact_hash
from sentinel.provenance import ProvenanceContext, create_trusted_provenance


class IngestedArtifact(BaseModel):
    """Canonical ingested representation of external content with trusted provenance.

    SECURITY INVARIANT:
    - `content` is the canonical extracted text inspected downstream.
    - `provenance.artifact_hash` MUST be equal to SHA256(canonical content).
    - Ingestion establishes provenance metadata ONLY; it does NOT imply content safety
      or grant execution authorization.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    content: str = Field(..., description="Canonical extracted text content.")
    provenance: ProvenanceContext = Field(
        ..., description="Gateway-assigned trusted provenance metadata."
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Non-security descriptive structural metadata (e.g. filename, url).",
    )


def ingest_text(
    content: str,
    *,
    client_id: str = "anonymous_client",
) -> IngestedArtifact:
    """Ingest raw direct caller text at the public gateway boundary.

    SECURITY BOUNDARY:
    Public/untrusted callers must NOT control trusted provenance metadata.
    This gateway entrypoint always generates a fresh, gateway-owned correlation ID.
    """
    return ingest_text_internal(
        content=content,
        client_id=client_id,
        correlation_id=str(uuid.uuid4()),
    )


def ingest_text_internal(
    content: str,
    *,
    correlation_id: str,
    client_id: str = "internal_caller",
) -> IngestedArtifact:
    """Trusted internal gateway ingestion allowing propagation of an existing correlation ID."""
    if not isinstance(content, str):
        raise TypeError(f"content must be a string, got {type(content).__name__}")

    if not correlation_id or not isinstance(correlation_id, str):
        raise ValueError("correlation_id must be a non-empty string for internal ingestion")

    canonical_content = content

    provenance = create_trusted_provenance(
        content=canonical_content,
        source_type="direct",
        source_id=f"client:{client_id}",
        workflow="public_api",
        content_type="text/plain",
        correlation_id=correlation_id,
    )

    return IngestedArtifact(
        content=canonical_content,
        provenance=provenance,
        metadata={"client_id": client_id},
    )


def extract_text_from_pdf(pdf_bytes: bytes) -> str:
    """Extract text content from raw PDF bytes.

    SECURITY INVARIANT:
    Extracted document text is untrusted content. Document metadata, titles, and
    embedded claims do not grant security clearance.
    """
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        extracted_pages: list[str] = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                extracted_pages.append(page_text)
        return "\n".join(extracted_pages)
    except Exception as e:
        raise ValueError(f"Failed to parse and extract text from PDF document: {e}") from e


def ingest_document(
    raw_content: bytes | str,
    filename: str,
    *,
    correlation_id: str | None = None,
) -> IngestedArtifact:
    """Ingest document files (TXT, Markdown, PDF) into canonical text.

    Security Rules:
    1. Extracts text into a canonical UTF-8 string representation.
    2. Hashing is performed strictly on the extracted canonical text.
    3. Filenames and structural extensions determine MIME metadata only, not trust.
    """
    assigned_correlation_id = correlation_id or str(uuid.uuid4())
    lower_filename = filename.lower()

    if lower_filename.endswith(".txt"):
        content_type = "text/plain"
        if isinstance(raw_content, bytes):
            canonical_content = raw_content.decode("utf-8")
        else:
            canonical_content = raw_content

    elif lower_filename.endswith((".md", ".markdown")):
        content_type = "text/markdown"
        if isinstance(raw_content, bytes):
            canonical_content = raw_content.decode("utf-8")
        else:
            canonical_content = raw_content

    elif lower_filename.endswith(".pdf"):
        content_type = "application/pdf"
        pdf_bytes = raw_content.encode("utf-8") if isinstance(raw_content, str) else raw_content
        canonical_content = extract_text_from_pdf(pdf_bytes)

    else:
        raise ValueError(f"Unsupported document format for filename '{filename}'")

    provenance = create_trusted_provenance(
        content=canonical_content,
        source_type="document",
        source_id=f"file:{filename}",
        workflow="document_ingestion",
        content_type=content_type,
        correlation_id=assigned_correlation_id,
    )

    return IngestedArtifact(
        content=canonical_content,
        provenance=provenance,
        metadata={"filename": filename},
    )