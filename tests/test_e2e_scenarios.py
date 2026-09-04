"""Tests for Phase 9 End-to-End Scenarios and Security Invariants."""

from decimal import Decimal
from pathlib import Path
import pytest

from sentinel.detection.detector import PromptInjectionDetector
from sentinel.detection.models import DetectionLabel
from sentinel.evaluation.e2e import (
    execute_e2e_pipeline,
    scan_adversarial_artifacts_for_detector_results,
)
from sentinel.policy.gate import TaskScope

CORPUS_PATH = Path("data/corpus")


@pytest.fixture(scope="module")
def shared_detector():
    """Module-scoped detector instance to avoid reloading weights across tests."""
    return PromptInjectionDetector()


def test_scenario_1_legitimate_purchase_executes(shared_detector):
    """Scenario 1: Benign artifact with compliant proposal results in ALLOW and execution."""
    benign_path = CORPUS_PATH / "benign" / "bulk_cable_accessory_quote_009.txt"
    task_scope = TaskScope(allowed_categories=["cable", "accessory"], max_budget=Decimal("5000.00"))

    result, logger = execute_e2e_pipeline(
        artifact_path=benign_path,
        ground_truth="BENIGN",
        scenario_name="Scenario 1: Legitimate Purchase",
        product_id="cat6_patch_cord",
        category="cable",
        quantity=2,
        unit_price=Decimal("1200.00"),  # ₹2,400 <= ₹5,000
        task_scope=task_scope,
        detector=shared_detector,
    )

    assert result.ground_truth == "BENIGN"
    assert result.detector_label == "SAFE"
    assert result.policy_decision == "ALLOW"
    assert result.executed is True
    assert "ACTION_EXECUTED" in result.audit_events
    assert "ACTION_BLOCKED" not in result.audit_events

    # Verify audit correlation
    correlated = logger.get_by_correlation_id(result.correlation_id)
    assert len(correlated) == 6
    assert [e.event_type.value for e in correlated] == [
        "INGESTED",
        "INSPECTION_ROUTED",
        "DETECTED",
        "ACTION_PROPOSED",
        "POLICY_DECIDED",
        "ACTION_EXECUTED",
    ]


def test_scenario_2_detected_attack_escalates_to_review(shared_detector):
    """Scenario 2: Malicious content detected by model causes REVIEW, preventing execution."""
    adv_scan = scan_adversarial_artifacts_for_detector_results(CORPUS_PATH, shared_detector)
    detected_artifacts = [k for k, v in adv_scan.items() if v.label == DetectionLabel.INJECTION]
    assert len(detected_artifacts) > 0, "Expected at least one detected adversarial artifact"

    target_file = CORPUS_PATH / "adversarial" / detected_artifacts[0]
    task_scope = TaskScope(allowed_categories=["cloud_service"], max_budget=Decimal("50000.00"))

    result, logger = execute_e2e_pipeline(
        artifact_path=target_file,
        ground_truth="ADVERSARIAL",
        scenario_name="Scenario 2: Detected Attack",
        product_id="cloud_storage_tier",
        category="cloud_service",  # Complies with TaskScope
        quantity=1,
        unit_price=Decimal("4000.00"),  # <= ₹5,000 auto-approval ceiling
        task_scope=task_scope,
        detector=shared_detector,
    )

    assert result.ground_truth == "ADVERSARIAL"
    assert result.detector_label == "INJECTION"
    # The decision must be REVIEW strictly due to the injection detection
    assert result.policy_decision == "REVIEW"
    assert "flagged detection evidence requires human review" in result.policy_reason
    assert result.executed is False
    assert "ACTION_BLOCKED" in result.audit_events
    assert "ACTION_EXECUTED" not in result.audit_events

    # Verify audit correlation
    correlated = logger.get_by_correlation_id(result.correlation_id)
    assert len(correlated) == 6
    assert [e.event_type.value for e in correlated] == [
        "INGESTED",
        "INSPECTION_ROUTED",
        "DETECTED",
        "ACTION_PROPOSED",
        "POLICY_DECIDED",
        "ACTION_BLOCKED",
    ]
    assert all(e.correlation_id == result.correlation_id for e in correlated)


def test_scenario_3_detector_miss_prevented_by_policy_gate(shared_detector):
    """Scenario 3: Detector false negative (SAFE) is STILL prevented by PolicyGate task scope."""
    adv_scan = scan_adversarial_artifacts_for_detector_results(CORPUS_PATH, shared_detector)
    false_negatives = [k for k, v in adv_scan.items() if v.label == DetectionLabel.SAFE]
    assert len(false_negatives) > 0, "Expected at least one actual detector false negative in corpus"

    selected_artifact = "monitor_category_substitution_014.md"
    if selected_artifact not in false_negatives:
        selected_artifact = false_negatives[0]

    target_file = CORPUS_PATH / "adversarial" / selected_artifact
    actual_det_result = adv_scan[selected_artifact]

    # Ground truth is ADVERSARIAL, but detector missed and said SAFE
    assert actual_det_result.label == DetectionLabel.SAFE

    # User delegated task scope: "laptop"
    task_scope = TaskScope(allowed_categories=["laptop"], max_budget=Decimal("50000.00"))

    # Unauthorized action proposal: "gift_card"
    result, logger = execute_e2e_pipeline(
        artifact_path=target_file,
        ground_truth="ADVERSARIAL",
        scenario_name="Scenario 3: Detector Miss + Unauthorized Action Proposal + Policy Gate Block",
        product_id="prepaid_gift_card",
        category="gift_card",  # VIOLATES SCOPE
        quantity=1,
        unit_price=Decimal("3000.00"),  # Within budget, but wrong category
        task_scope=task_scope,
        detector=shared_detector,
    )

    # Verify critical invariants
    assert result.ground_truth == "ADVERSARIAL"
    assert result.detector_label == "SAFE"
    assert result.policy_decision == "DENY"
    assert "Violates delegated task scope: category 'gift_card'" in result.policy_reason
    assert result.executed is False
    assert "ACTION_BLOCKED" in result.audit_events
    assert "ACTION_EXECUTED" not in result.audit_events

    # Verify audit correlation
    correlated = logger.get_by_correlation_id(result.correlation_id)
    assert len(correlated) == 6
    assert [e.event_type.value for e in correlated] == [
        "INGESTED",
        "INSPECTION_ROUTED",
        "DETECTED",
        "ACTION_PROPOSED",
        "POLICY_DECIDED",
        "ACTION_BLOCKED",
    ]
    assert all(e.correlation_id == result.correlation_id for e in correlated)