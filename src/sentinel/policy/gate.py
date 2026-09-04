"""Deterministic Policy Gate for commercial action authorization."""

from decimal import Decimal
from enum import Enum
import secrets
from pydantic import BaseModel, ConfigDict, Field

from sentinel.agent.reasoning import ActionProposal, ActionType
from sentinel.detection.models import DetectionLabel, DetectionResult
from sentinel.provenance import ProvenanceContext

AUTO_APPROVE_MAX_LIMIT = Decimal("5000.00")
REVIEW_MAX_LIMIT = Decimal("50000.00")


class PolicyDecisionType(str, Enum):
    """The exclusive deterministic authorization verdicts produced by the Policy Gate."""

    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


class TaskScope(BaseModel):
    """Minimal delegated task scope authorized by the user."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_categories: list[str] = Field(..., description="Categories authorized by the user (e.g. ['laptop']).")
    max_budget: Decimal | None = Field(
        default=None,
        gt=Decimal("0.00"),
        description="Optional user-stipulated delegated budget cap.",
    )


class PolicyDecision(BaseModel):
    """Immutable authorization verdict rendered by the deterministic Policy Gate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision: PolicyDecisionType = Field(..., description="Authorization outcome: ALLOW, REVIEW, or DENY.")
    reason: str = Field(..., min_length=1, description="Deterministic explanation for the decision.")
    correlation_id: str = Field(..., min_length=1, description="Correlation identifier for tracing.")
    proposal_fingerprint: str = Field(..., description="Deterministic SHA-256 fingerprint of the evaluated ActionProposal.")
    auth_token: str | None = Field(
        default=None,
        description="Opaque in-process authorization token issued by PolicyGate for ALLOW decisions.",
    )


class PolicyGate:
    """The deterministic authorization authority for consequential commerce actions.

    SECURITY INVARIANTS:
    - Independent of LLMs, agent claims, and probabilistic detector scores.
    - Fail-closed: unsupported action types, scope breaches, or rule violations produce DENY.
    - Spending policy:
        total <= ₹5,000 -> ALLOW
        ₹5,000 < total <= ₹50,000 -> REVIEW
        total > ₹50,000 -> DENY
    - Scope enforcement: if task_scope is provided, proposal category and budget must match.
    - An in-process token registry ensures only decisions issued by this PolicyGate can execute.
    """

    def __init__(
        self,
        auto_approve_limit: Decimal = AUTO_APPROVE_MAX_LIMIT,
        review_limit: Decimal = REVIEW_MAX_LIMIT,
    ) -> None:
        if auto_approve_limit <= Decimal("0.00") or review_limit <= auto_approve_limit:
            raise ValueError("Invalid limit configuration: auto_approve_limit must be > 0 and < review_limit")
        self.auto_approve_limit = auto_approve_limit
        self.review_limit = review_limit
        # In-process registry of legitimate ALLOW authorizations: (fingerprint, correlation_id, auth_token)
        self._issued_authorizations: set[tuple[str, str, str]] = set()

    def is_authorized(self, proposal: ActionProposal, decision: PolicyDecision) -> bool:
        """Verify that an ALLOW decision was authentically issued by this PolicyGate for this proposal."""
        if decision.decision != PolicyDecisionType.ALLOW or not decision.auth_token:
            return False
        if proposal.correlation_id != decision.correlation_id:
            return False
        if proposal.compute_fingerprint() != decision.proposal_fingerprint:
            return False
        return (decision.proposal_fingerprint, decision.correlation_id, decision.auth_token) in self._issued_authorizations

    def evaluate(
        self,
        proposal: ActionProposal,
        provenance: ProvenanceContext | None = None,
        detection_result: DetectionResult | None = None,
        task_scope: TaskScope | None = None,
    ) -> PolicyDecision:
        """Evaluate an ActionProposal against deterministic spending and task-scope rules."""
        if not isinstance(proposal, ActionProposal):
            raise TypeError(f"proposal must be an ActionProposal instance, got {type(proposal).__name__}")

        fingerprint = proposal.compute_fingerprint()

        # Invariant 1: Correlation alignment check
        if provenance and provenance.correlation_id != proposal.correlation_id:
            return PolicyDecision(
                decision=PolicyDecisionType.DENY,
                reason=f"Correlation ID mismatch between proposal ({proposal.correlation_id}) and provenance ({provenance.correlation_id})",
                correlation_id=proposal.correlation_id,
                proposal_fingerprint=fingerprint,
            )

        # Invariant 2: Action type support
        if proposal.action_type != ActionType.PURCHASE:
            return PolicyDecision(
                decision=PolicyDecisionType.DENY,
                reason=f"Unsupported action type '{proposal.action_type}' rejected by Policy Gate",
                correlation_id=proposal.correlation_id,
                proposal_fingerprint=fingerprint,
            )

        # Invariant 3: Currency check
        if proposal.currency != "INR":
            return PolicyDecision(
                decision=PolicyDecisionType.DENY,
                reason=f"Currency '{proposal.currency}' rejected. Policy Gate only authorizes INR transactions.",
                correlation_id=proposal.correlation_id,
                proposal_fingerprint=fingerprint,
            )

        # Invariant 4: Delegated task scope enforcement
        if task_scope is not None:
            normalized_allowed = [cat.lower().strip() for cat in task_scope.allowed_categories]
            if proposal.category.lower().strip() not in normalized_allowed:
                return PolicyDecision(
                    decision=PolicyDecisionType.DENY,
                    reason=(
                        f"Violates delegated task scope: category '{proposal.category}' "
                        f"is not in authorized categories {task_scope.allowed_categories}."
                    ),
                    correlation_id=proposal.correlation_id,
                    proposal_fingerprint=fingerprint,
                )

            if task_scope.max_budget is not None and proposal.total > task_scope.max_budget:
                return PolicyDecision(
                    decision=PolicyDecisionType.DENY,
                    reason=(
                        f"Violates delegated task scope: purchase total ₹{proposal.total} "
                        f"exceeds user-delegated budget of ₹{task_scope.max_budget}."
                    ),
                    correlation_id=proposal.correlation_id,
                    proposal_fingerprint=fingerprint,
                )

        # Invariant 5: High-risk detection override (escalates auto-approve to REVIEW)
        is_flagged_injection = (
            detection_result is not None and detection_result.label == DetectionLabel.INJECTION
        )

        # Invariant 6: Deterministic spending limits
        if proposal.total <= self.auto_approve_limit:
            if is_flagged_injection:
                return PolicyDecision(
                    decision=PolicyDecisionType.REVIEW,
                    reason=(
                        f"Purchase total ₹{proposal.total} is within auto-approval limit, "
                        "but flagged detection evidence requires human review."
                    ),
                    correlation_id=proposal.correlation_id,
                    proposal_fingerprint=fingerprint,
                )

            token = secrets.token_hex(16)
            self._issued_authorizations.add((fingerprint, proposal.correlation_id, token))
            return PolicyDecision(
                decision=PolicyDecisionType.ALLOW,
                reason=f"Purchase total ₹{proposal.total} is within delegated spending limit (<= ₹{self.auto_approve_limit}).",
                correlation_id=proposal.correlation_id,
                proposal_fingerprint=fingerprint,
                auth_token=token,
            )

        if proposal.total <= self.review_limit:
            return PolicyDecision(
                decision=PolicyDecisionType.REVIEW,
                reason=(
                    f"Purchase total ₹{proposal.total} exceeds automatic approval limit (₹{self.auto_approve_limit}) "
                    f"and requires review (<= ₹{self.review_limit})."
                ),
                correlation_id=proposal.correlation_id,
                proposal_fingerprint=fingerprint,
            )

        return PolicyDecision(
            decision=PolicyDecisionType.DENY,
            reason=f"Purchase total ₹{proposal.total} exceeds maximum permitted spending limit (> ₹{self.review_limit}).",
            correlation_id=proposal.correlation_id,
            proposal_fingerprint=fingerprint,
        )