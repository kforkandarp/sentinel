"""Core schemas and trusted provenance construction for Sentinel (Phase 1)."""

import re
import uuid
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.hashing import compute_artifact_hash

# Valid hex pattern for SHA-256 (64 lowercase hex characters)
SHA256_HEX_REGEX = re.compile(r"^[0-9a-f]{64}$")

SourceType = Literal["direct", "document", "web"]
WorkflowType = Literal["public_api", "document_ingestion", "web_ingestion"]


class ProvenanceContext(BaseModel):
    """Metadata created by trusted application code describing content origin and identity.

    TERMINOLOGY & SECURITY INVARIANT:
    - Provenance assignment is performed exclusively by trusted internal code.
    - Provenance describes origin and identity ONLY.
    - Provenance does NOT mean the underlying content is trusted, safe, benign,
      sanitized, verified, or authorized.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_type: SourceType = Field(
        ..., description="Origin channel of content (direct, document, web)."
    )
    source_id: str = Field(
        ...,
        min_length=1,
        description=(
            "Origin identifier (e.g. URL, client label, document path). "
            "SECURITY: This is provenance metadata only. It is NOT an authenticated "
            "identity or authorization principal, and must never be used as evidence "
            "that the caller or content is trusted or authorized."
        ),
    )
    artifact_id: str = Field(
        ..., description="Unique instance identifier for this ingested artifact."
    )
    artifact_hash: str = Field(
        ..., description="Deterministic SHA-256 hexadecimal digest of artifact bytes."
    )
    content_type: str = Field(
        ...,
        min_length=1,
        description=(
            "MIME content representation (e.g. text/plain, application/pdf). "
            "NOTE: This is structural representation metadata only; it does NOT "
            "imply safety, sanitization, or verified trust."
        ),
    )
    workflow: WorkflowType = Field(
        ..., description="Gateway intake workflow through which content entered Sentinel."
    )
    correlation_id: str = Field(
        ..., description="Unique lifecycle correlation identifier."
    )

    @field_validator("artifact_hash")
    @classmethod
    def validate_artifact_hash(cls, v: str) -> str:
        if not SHA256_HEX_REGEX.match(v):
            raise ValueError(
                "artifact_hash must be a valid 64-character lowercase SHA-256 hex digest"
            )
        return v

    @field_validator("artifact_id", "correlation_id")
    @classmethod
    def validate_uuid_format(cls, v: str) -> str:
        try:
            uuid.UUID(v)
        except ValueError:
            raise ValueError("ID must be a valid UUID string")
        return v


class UntrustedCallerPayload(BaseModel):
    """Represents untrusted external payload submitted to the gateway.

    All fields on this model are untrusted by definition. Caller-supplied metadata
    (including declared formats or identifiers) must never be treated as trusted
    gateway provenance.
    """

    model_config = ConfigDict(extra="allow")

    content: str = Field(..., description="The raw untrusted content text/body.")
    declared_content_type: str | None = Field(
        default=None,
        description="Optional format declared by untrusted caller; not verified.",
    )


def create_trusted_provenance(
    *,
    content: bytes | str,
    source_type: SourceType,
    source_id: str,
    workflow: WorkflowType,
    content_type: str = "text/plain",
    correlation_id: str | None = None,
    artifact_id: str | None = None,
) -> ProvenanceContext:
    """Factory constructing ProvenanceContext at the gateway security boundary.

    CONTRACT & SECURITY BOUNDARY:
    - This constructor is strictly for trusted internal application code.
    - Untrusted/public input must never be passed directly into this function.
    - Omitted IDs are automatically generated as fresh UUIDs.
    - Supplied IDs are trusted internal values (e.g. upstream correlation propagation)
      and are strictly validated by ProvenanceContext.
    """
    assigned_correlation_id = correlation_id or str(uuid.uuid4())
    assigned_artifact_id = artifact_id or str(uuid.uuid4())
    computed_hash = compute_artifact_hash(content)

    return ProvenanceContext(
        source_type=source_type,
        source_id=source_id,
        artifact_id=assigned_artifact_id,
        artifact_hash=computed_hash,
        content_type=content_type,
        workflow=workflow,
        correlation_id=assigned_correlation_id,
    )


def gateway_ingest_untrusted_direct(
    caller_payload: UntrustedCallerPayload | dict,
    *,
    client_id: str = "anonymous_client",
    correlation_id: str | None = None,
) -> tuple[str, ProvenanceContext]:
    """Demonstration boundary: trusted intake of an untrusted direct caller payload.

    Boundary Rules:
    1. Untrusted caller input cannot dictate trusted origin, workflow, or IDs.
    2. Direct textual input received via this gateway boundary is assigned gateway-established
       content_type='text/plain'. Any caller-declared content type remains unverified
       caller metadata and does not override gateway attribution.
    3. `source_id` records intake origin metadata (`client:<id>`). It is NOT an authenticated
       identity or authorization credential.
    4. If an existing correlation_id is provided by trusted internal orchestration, it is
       propagated; otherwise a fresh one is generated.
    """
    if isinstance(caller_payload, dict):
        parsed_payload = UntrustedCallerPayload.model_validate(caller_payload)
    else:
        parsed_payload = caller_payload

    trusted_provenance = create_trusted_provenance(
        content=parsed_payload.content,
        source_type="direct",
        source_id=f"client:{client_id}",
        workflow="public_api",
        content_type="text/plain",
        correlation_id=correlation_id,
    )
    return parsed_payload.content, trusted_provenance