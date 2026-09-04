"""Tests for Phase 4 Gateway Ingestion, Document Extraction, and Provenance."""

import pytest
from pydantic import ValidationError

from sentinel.gateway.ingestion import (
    IngestedArtifact,
    ingest_document,
    ingest_text,
    ingest_text_internal,
)
from sentinel.hashing import compute_artifact_hash
from sentinel.inspection.models import InspectionRoute
from sentinel.inspection.router import InspectionRouter


# --- Helpers ---


def _create_minimal_pdf_bytes(text: str) -> bytes:
    """Generate minimal valid PDF bytes containing actual embedded text in a content stream."""
    escaped_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream_content = f"BT\n/F1 12 Tf\n72 712 Td\n({escaped_text}) Tj\nET\n".encode("latin-1")
    stream_len = len(stream_content)

    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        b"4 0 obj\n<< /Length " + str(stream_len).encode("ascii") + b" >>\nstream\n"
        + stream_content +
        b"endstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000244 00000 n \n"
        b"0000000350 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n426\n%%EOF\n"
    )


# --- Direct Ingestion Tests ---


def test_public_direct_text_ingestion_establishes_trusted_provenance():
    artifact = ingest_text("Payment request for 400 USD", client_id="user_abc")

    assert isinstance(artifact, IngestedArtifact)
    assert artifact.content == "Payment request for 400 USD"
    assert artifact.provenance.source_type == "direct"
    assert artifact.provenance.source_id == "client:user_abc"
    assert artifact.provenance.workflow == "public_api"
    assert artifact.provenance.content_type == "text/plain"
    assert artifact.provenance.artifact_hash == compute_artifact_hash(artifact.content)
    assert len(artifact.provenance.correlation_id) > 0


def test_public_direct_text_ingestion_generates_own_correlation_id():
    """Security Boundary: Public caller cannot pass correlation_id into ingest_text()."""
    with pytest.raises(TypeError):
        ingest_text("Hello", correlation_id="caller-supplied-id")  # type: ignore


def test_internal_text_ingestion_propagates_trusted_correlation_id():
    """Trusted Path: Internal callers can propagate an existing correlation ID."""
    custom_cid = "12345678-1234-5678-1234-567812345678"
    artifact = ingest_text_internal("Hello", correlation_id=custom_cid)
    assert artifact.provenance.correlation_id == custom_cid


def test_direct_text_ingestion_rejects_invalid_runtime_type():
    with pytest.raises(TypeError, match="content must be a string"):
        ingest_text(12345)  # type: ignore


# --- Document Ingestion Tests ---


def test_ingest_txt_document():
    raw_text = "Vendor terms and conditions."
    artifact = ingest_document(raw_text, "terms.txt")

    assert artifact.content == raw_text
    assert artifact.provenance.source_type == "document"
    assert artifact.provenance.source_id == "file:terms.txt"
    assert artifact.provenance.workflow == "document_ingestion"
    assert artifact.provenance.content_type == "text/plain"
    assert artifact.provenance.artifact_hash == compute_artifact_hash(raw_text)


def test_ingest_markdown_document():
    raw_md = "# Invoice\n**Amount**: $500"
    artifact = ingest_document(raw_md, "invoice.md")

    assert artifact.content == raw_md
    assert artifact.provenance.content_type == "text/markdown"
    assert artifact.provenance.workflow == "document_ingestion"


def test_ingest_pdf_document():
    """Verify PDF ingestion actually extracts embedded textual content."""
    known_text = "Vendor Invoice 402 - Total Due: 1500 USD"
    pdf_bytes = _create_minimal_pdf_bytes(known_text)
    artifact = ingest_document(pdf_bytes, "doc.pdf")

    assert artifact.provenance.content_type == "application/pdf"
    assert artifact.provenance.source_type == "document"
    assert known_text in artifact.content
    assert artifact.provenance.artifact_hash == compute_artifact_hash(artifact.content)


def test_ingest_unsupported_document_extension_fails():
    with pytest.raises(ValueError, match="Unsupported document format"):
        ingest_document("data", "script.exe")


def test_ingest_malformed_pdf_fails_explicitly():
    with pytest.raises(ValueError, match="Failed to parse and extract text from PDF"):
        ingest_document(b"%PDF-malformed-garbage-bytes", "corrupted.pdf")


# --- Integration with Downstream Inspection Router ---


def test_ingested_artifact_feeds_inspection_router_cleanly():
    """Verify IngestedArtifact seamlessly feeds InspectionRouter and obeys hash invariants."""
    artifact = ingest_text("Legitimate invoice text", client_id="partner_9")

    router = InspectionRouter()
    decision = router.route(artifact.content, artifact.provenance)

    assert decision.route == InspectionRoute.DEEP_INSPECT
    assert decision.cached_result is None


def test_ingested_artifact_contains_no_authorization_fields():
    forbidden = {
        "is_safe",
        "safe",
        "authorized",
        "is_authorized",
        "allow",
        "deny",
        "policy_verdict",
        "action_allowed",
    }
    artifact_fields = set(IngestedArtifact.model_fields.keys())
    assert not forbidden.intersection(artifact_fields)