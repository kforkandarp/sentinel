"""Integration tests for the Sentinel Gateway FastAPI REST endpoints."""


from pathlib import Path
import io
from starlette.testclient import TestClient

from sentinel.app import app

client = TestClient(app)
CORPUS_PATH = Path("data/corpus")


def test_health_endpoint():
    """Verify operational health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "sentinel-gateway"


def test_scan_scenario_1_legitimate_purchase_allows_and_executes():
    """Scenario 1: Benign input with compliant proposal leads to ALLOW and execution."""
    benign_path = CORPUS_PATH / "benign" / "bulk_cable_accessory_quote_009.txt"
    content = benign_path.read_text(encoding="utf-8")

    payload = {
        "content": content,
        "product_id": "cat6_spool_100",
        "category": "cable",
        "quantity": 2,
        "unit_price": 1200.00,  # Total ₹2,400 <= ₹5,000
        "task_scope": {
            "allowed_categories": ["cable", "accessory"],
            "max_budget": 5000.00,
        },
    }

    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["detector_label"] == "SAFE"
    assert data["policy_decision"] == "ALLOW"
    assert data["executed"] is True
    assert "ACTION_EXECUTED" in data["audit_events"]
    assert "auth_token" not in data


def test_scan_scenario_2_detected_attack_blocks_execution():
    """Scenario 2: Adversarial input flagged as INJECTION escalates to REVIEW, blocking execution."""
    adv_path = CORPUS_PATH / "adversarial" / "wholesale_catalog_hidden_instruction_021.txt"
    content = adv_path.read_text(encoding="utf-8")

    payload = {
        "content": content,
        "product_id": "cloud_tier_compute",
        "category": "electronics",
        "quantity": 1,
        "unit_price": 4000.00,  # <= ₹5,000
        "task_scope": {
            "allowed_categories": ["electronics"],
            "max_budget": 50000.00,
        },
    }

    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["detector_label"] == "INJECTION"
    assert data["policy_decision"] == "REVIEW"
    assert data["executed"] is False
    assert "ACTION_BLOCKED" in data["audit_events"]


def test_scan_scenario_3_detector_miss_denied_by_policy_scope():
    """Scenario 3: Detector False Negative (SAFE) is still blocked by Policy Gate task scope."""
    adv_path = CORPUS_PATH / "adversarial" / "monitor_category_substitution_014.md"
    content = adv_path.read_text(encoding="utf-8")

    payload = {
        "content": content,
        "product_id": "digital_gift_card",
        "category": "gift_card",  # Outside allowed scope ['laptop']
        "quantity": 1,
        "unit_price": 3000.00,
        "task_scope": {
            "allowed_categories": ["laptop"],
            "max_budget": 50000.00,
        },
    }

    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["detector_label"] == "SAFE"
    assert data["policy_decision"] == "DENY"
    assert "Violates delegated task scope" in data["policy_reason"]
    assert data["executed"] is False
    assert "ACTION_BLOCKED" in data["audit_events"]


def test_ingest_file_txt():
    """Verify multipart file upload ingestion with plain text."""
    sample_text = "Sample purchase order notes."
    files = {"file": ("test_order.txt", io.BytesIO(sample_text.encode("utf-8")), "text/plain")}
    response = client.post("/ingest-file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test_order.txt"
    assert data["extracted_content"] == sample_text
    assert data["content_type"] == "text/plain"


def test_ingest_file_markdown():
    """Verify multipart file upload ingestion with Markdown."""
    sample_md = "# Title\n\n- Item 1\n- Item 2"
    files = {"file": ("listing.md", io.BytesIO(sample_md.encode("utf-8")), "text/markdown")}
    response = client.post("/ingest-file", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "listing.md"
    assert "Item 1" in data["extracted_content"]
    assert data["content_type"] == "text/markdown"


def test_ingest_file_pdf():
    """Verify multipart file upload ingestion with real Phase 7 corpus PDF."""
    pdf_path = CORPUS_PATH / "benign" / "standard_commercial_warranty_012.pdf"
    if pdf_path.exists():
        pdf_bytes = pdf_path.read_bytes()
        files = {"file": ("warranty.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
        response = client.post("/ingest-file", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["filename"] == "warranty.pdf"
        assert len(data["extracted_content"]) > 0
        assert data["content_type"] == "application/pdf"


def test_ingest_file_unsupported_type_fails():
    """Verify unsupported file extensions are cleanly rejected."""
    files = {"file": ("executable.exe", io.BytesIO(b"binarycontent"), "application/octet-stream")}
    response = client.post("/ingest-file", files=files)
    assert response.status_code == 400
    assert "Unsupported document format" in response.json()["detail"]