"""Tests for Phase 5 Agent Reasoning, Deterministic Policy Gate, and Execution Boundary."""

from decimal import Decimal
import uuid
import pytest
from pydantic import ValidationError

from sentinel.agent.reasoning import ActionProposal, ActionType, CommerceAgent
from sentinel.detection.models import DetectionLabel, DetectionResult
from sentinel.execution.executor import ActionExecutor, ExecutionBlockedError
from sentinel.policy.gate import PolicyDecision, PolicyDecisionType, PolicyGate, TaskScope
from sentinel.provenance import create_trusted_provenance


# --- Spending Limit Deterministic Boundary Tests ---


@pytest.mark.parametrize(
    "unit_price,expected_verdict,expected_reason_substr",
    [
        (Decimal("4000.00"), PolicyDecisionType.ALLOW, "within delegated spending limit"),
        (Decimal("5000.00"), PolicyDecisionType.ALLOW, "within delegated spending limit"),
        (Decimal("5001.00"), PolicyDecisionType.REVIEW, "requires review"),
        (Decimal("50000.00"), PolicyDecisionType.REVIEW, "requires review"),
        (Decimal("50001.00"), PolicyDecisionType.DENY, "exceeds maximum permitted spending limit"),
    ],
)
def test_spending_policy_exact_boundaries(unit_price, expected_verdict, expected_reason_substr):
    """Verify deterministic spending boundaries: <=5000 ALLOW, 5001-50000 REVIEW, >50000 DENY."""
    gate = PolicyGate()
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="prod_test",
        category="laptop",
        quantity=1,
        unit_price=unit_price,
        total=unit_price,
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )
    decision = gate.evaluate(proposal)
    assert decision.decision == expected_verdict
    assert expected_reason_substr in decision.reason


# --- Delegated Task Scope Tests ---


def test_policy_gate_denies_proposal_violating_task_scope_category():
    """Demo Invariant: Agent proposing an unauthorized category is DENIED even if price is low."""
    gate = PolicyGate()
    task_scope = TaskScope(allowed_categories=["laptop"], max_budget=Decimal("50000.00"))

    # Attacker redirects agent to buy gift cards for ₹4,000
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="card_123",
        category="gift_card",
        quantity=1,
        unit_price=Decimal("4000.00"),
        total=Decimal("4000.00"),
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )

    decision = gate.evaluate(proposal, task_scope=task_scope)
    assert decision.decision == PolicyDecisionType.DENY
    assert "Violates delegated task scope: category 'gift_card'" in decision.reason


def test_policy_gate_denies_proposal_exceeding_delegated_task_budget():
    """Demo Invariant: Proposal exceeding user-delegated budget is DENIED."""
    gate = PolicyGate()
    task_scope = TaskScope(allowed_categories=["laptop"], max_budget=Decimal("30000.00"))

    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="laptop_pro",
        category="laptop",
        quantity=1,
        unit_price=Decimal("45000.00"),
        total=Decimal("45000.00"),
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )

    decision = gate.evaluate(proposal, task_scope=task_scope)
    assert decision.decision == PolicyDecisionType.DENY
    assert "exceeds user-delegated budget of ₹30000.00" in decision.reason


def test_policy_gate_allows_proposal_within_task_scope_and_budget():
    """Legitimate purchase matching task scope and budget is ALLOWED."""
    gate = PolicyGate()
    task_scope = TaskScope(allowed_categories=["laptop"], max_budget=Decimal("50000.00"))

    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="laptop_basic",
        category="laptop",
        quantity=1,
        unit_price=Decimal("4500.00"),
        total=Decimal("4500.00"),
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )

    decision = gate.evaluate(proposal, task_scope=task_scope)
    assert decision.decision == PolicyDecisionType.ALLOW


# --- Proposal Validation & Tamper Resistance ---


def test_proposal_rejects_extra_authorization_fields_and_mismatched_totals():
    """Security Invariant: Cannot inject authorization flags; calculation must balance."""
    cid = str(uuid.uuid4())

    with pytest.raises(ValidationError):
        ActionProposal(
            action_type=ActionType.PURCHASE,
            product_id="prod_1",
            category="laptop",
            quantity=1,
            unit_price=Decimal("100.00"),
            total=Decimal("100.00"),
            currency="INR",
            correlation_id=cid,
            is_authorized=True,  # type: ignore
        )

    with pytest.raises(ValidationError, match="Total mismatch"):
        ActionProposal(
            action_type=ActionType.PURCHASE,
            product_id="prod_1",
            category="laptop",
            quantity=3,
            unit_price=Decimal("100.00"),
            total=Decimal("250.00"),  # Mismatch
            currency="INR",
            correlation_id=cid,
        )


# --- Detector Independence & Security Invariants ---


def test_detector_false_negative_does_not_bypass_policy_gate():
    """Core Security Invariant: Detector false negative (SAFE) CANNOT authorize an unauthorized purchase."""
    gate = PolicyGate()
    detector_miss = DetectionResult(label=DetectionLabel.SAFE, score=0.05)
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="high_value_server",
        category="server",
        quantity=1,
        unit_price=Decimal("50001.00"),
        total=Decimal("50001.00"),
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )

    decision = gate.evaluate(proposal, detection_result=detector_miss)
    assert decision.decision == PolicyDecisionType.DENY


def test_detector_injection_flag_moves_low_value_to_review():
    """Security Invariant: Detector evidence cannot grant authorization, but can escalate to REVIEW."""
    gate = PolicyGate()
    detector_flag = DetectionResult(label=DetectionLabel.INJECTION, score=0.95)
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="cheap_item",
        category="accessory",
        quantity=1,
        unit_price=Decimal("4000.00"),
        total=Decimal("4000.00"),
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )

    decision = gate.evaluate(proposal, detection_result=detector_flag)
    assert decision.decision == PolicyDecisionType.REVIEW
    assert "flagged detection evidence requires human review" in decision.reason


def test_correlation_mismatch_fails_closed():
    """Fail-Closed: Proposal and Provenance with divergent correlation IDs produce DENY."""
    gate = PolicyGate()
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="item_1",
        category="cable",
        quantity=1,
        unit_price=Decimal("100.00"),
        total=Decimal("100.00"),
        currency="INR",
        correlation_id=str(uuid.uuid4()),
    )
    prov = create_trusted_provenance(
        content="Order item",
        source_type="direct",
        source_id="client:test",
        workflow="public_api",
        correlation_id=str(uuid.uuid4()),
    )

    decision = gate.evaluate(proposal, provenance=prov)
    assert decision.decision == PolicyDecisionType.DENY
    assert "Correlation ID mismatch" in decision.reason


# --- Execution Boundary Tests ---


def test_executor_allows_execution_only_on_legitimate_policy_allow():
    """Boundary Enforcement: Action executes on legitimate PolicyGate ALLOW."""
    gate = PolicyGate()
    executor = ActionExecutor(policy_gate=gate)
    cid = str(uuid.uuid4())
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="item_10",
        category="laptop",
        quantity=2,
        unit_price=Decimal("1000.00"),
        total=Decimal("2000.00"),
        currency="INR",
        correlation_id=cid,
    )

    allow_decision = gate.evaluate(proposal)
    assert allow_decision.decision == PolicyDecisionType.ALLOW

    exec_result = executor.execute(proposal, allow_decision)
    assert exec_result.success is True
    assert len(executor.executed_actions) == 1


def test_executor_rejects_caller_fabricated_allow_decision():
    """Security Invariant: Fabricated PolicyDecision(ALLOW) not issued by PolicyGate is rejected."""
    gate = PolicyGate()
    executor = ActionExecutor(policy_gate=gate)
    cid = str(uuid.uuid4())
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="item_10",
        category="laptop",
        quantity=1,
        unit_price=Decimal("2000.00"),
        total=Decimal("2000.00"),
        currency="INR",
        correlation_id=cid,
    )

    # Fabricate a decision manually without PolicyGate.evaluate()
    fabricated_decision = PolicyDecision(
        decision=PolicyDecisionType.ALLOW,
        reason="Attacker self-authorized",
        correlation_id=cid,
        proposal_fingerprint=proposal.compute_fingerprint(),
        auth_token="unregistered-fake-token",
    )

    with pytest.raises(ExecutionBlockedError, match="not authentically authorized"):
        executor.execute(proposal, fabricated_decision)

    assert len(executor.executed_actions) == 0


def test_executor_rejects_decision_for_different_proposal():
    """Security Invariant: Legitimate ALLOW for Proposal A cannot authorize Proposal B."""
    gate = PolicyGate()
    executor = ActionExecutor(policy_gate=gate)
    shared_cid = str(uuid.uuid4())

    proposal_a = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="item_a",
        category="mouse",
        quantity=1,
        unit_price=Decimal("2000.00"),
        total=Decimal("2000.00"),
        currency="INR",
        correlation_id=shared_cid,
    )
    decision_for_a = gate.evaluate(proposal_a)

    proposal_b = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="item_b",
        category="keyboard",
        quantity=1,
        unit_price=Decimal("4000.00"),
        total=Decimal("4000.00"),
        currency="INR",
        correlation_id=shared_cid,
    )

    with pytest.raises(ExecutionBlockedError, match="does not match actual proposal fingerprint"):
        executor.execute(proposal_b, decision_for_a)

    assert len(executor.executed_actions) == 0


@pytest.mark.parametrize(
    "unit_price,expected_decision",
    [
        (Decimal("10000.00"), PolicyDecisionType.REVIEW),
        (Decimal("90000.00"), PolicyDecisionType.DENY),
    ],
)
def test_executor_blocks_execution_on_review_and_deny(unit_price, expected_decision):
    """Execution is strictly blocked on both REVIEW and DENY verdicts."""
    gate = PolicyGate()
    executor = ActionExecutor(policy_gate=gate)
    cid = str(uuid.uuid4())
    proposal = ActionProposal(
        action_type=ActionType.PURCHASE,
        product_id="item_10",
        category="laptop",
        quantity=1,
        unit_price=unit_price,
        total=unit_price,
        currency="INR",
        correlation_id=cid,
    )

    decision = gate.evaluate(proposal)
    assert decision.decision == expected_decision

    with pytest.raises(ExecutionBlockedError, match=f"Policy Gate verdict is '{expected_decision.value}'"):
        executor.execute(proposal, decision)

    assert len(executor.executed_actions) == 0


def test_agent_generates_valid_proposal_without_execution_power():
    """Verify CommerceAgent produces structured proposals but cannot execute actions."""
    agent = CommerceAgent()
    cid = str(uuid.uuid4())
    proposal = agent.propose_purchase(
        product_id="laptop_dock",
        category="dock",
        quantity=2,
        unit_price="2200.00",
        correlation_id=cid,
    )

    assert isinstance(proposal, ActionProposal)
    assert proposal.total == Decimal("4400.00")
    assert not hasattr(agent, "execute")
    assert not hasattr(agent, "authorize")
def test_task_scope_rejects_non_positive_budget():
    with pytest.raises(ValidationError):
        TaskScope(allowed_categories=["laptop"], max_budget=Decimal("0.00"))
    with pytest.raises(ValidationError):
        TaskScope(allowed_categories=["laptop"], max_budget=Decimal("-10.00"))