"""Execution boundary ensuring actions occur ONLY upon Policy Gate ALLOW decisions."""

from pydantic import BaseModel, ConfigDict, Field

from sentinel.agent.reasoning import ActionProposal
from sentinel.policy.gate import PolicyDecision, PolicyDecisionType, PolicyGate


class ExecutionResult(BaseModel):
    """Result of an executed commercial action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    success: bool = Field(..., description="Whether execution was completed.")
    action_id: str = Field(..., description="Identifier of the executed action.")
    details: dict[str, str] = Field(default_factory=dict, description="Execution findings/details.")
    correlation_id: str = Field(..., description="Correlation identifier.")


class ExecutionBlockedError(PermissionError):
    """Raised when an unapproved or unauthorized action attempts to reach execution."""


class ActionExecutor:
    """Consequential action execution boundary.

    SECURITY INVARIANTS:
    - Actions can ONLY proceed if accompanied by an authentic PolicyGate ALLOW decision.
    - Fabricated PolicyDecision instances not issued by the PolicyGate are rejected.
    - Rejects execution on REVIEW or DENY with ExecutionBlockedError.
    """

    def __init__(self, policy_gate: PolicyGate) -> None:
        if not isinstance(policy_gate, PolicyGate):
            raise TypeError("policy_gate must be a valid PolicyGate instance")
        self._policy_gate = policy_gate
        self._executed_actions: list[str] = []

    @property
    def executed_actions(self) -> list[str]:
        return list(self._executed_actions)

    def execute(
        self,
        proposal: ActionProposal,
        policy_decision: PolicyDecision,
    ) -> ExecutionResult:
        """Execute consequential commerce action strictly bounded by Policy Gate authorization."""
        if not isinstance(proposal, ActionProposal):
            raise TypeError("proposal must be an ActionProposal instance")

        if not isinstance(policy_decision, PolicyDecision):
            raise TypeError("policy_decision must be a PolicyDecision instance")

        # Invariant 1: Correlation binding
        if proposal.correlation_id != policy_decision.correlation_id:
            raise ExecutionBlockedError(
                f"Execution rejected: proposal correlation_id ({proposal.correlation_id}) "
                f"does not match policy_decision correlation_id ({policy_decision.correlation_id})"
            )

        # Invariant 2: Consequential actions execute ONLY on ALLOW
        if policy_decision.decision != PolicyDecisionType.ALLOW:
            raise ExecutionBlockedError(
                f"Execution blocked: Policy Gate verdict is '{policy_decision.decision.value}'. "
                f"Reason: {policy_decision.reason}"
            )

        # Invariant 3: Proposal fingerprint binding
        computed_fingerprint = proposal.compute_fingerprint()
        if policy_decision.proposal_fingerprint != computed_fingerprint:
            raise ExecutionBlockedError(
                f"Execution rejected: decision proposal_fingerprint ({policy_decision.proposal_fingerprint}) "
                f"does not match actual proposal fingerprint ({computed_fingerprint})"
            )

        # Invariant 4: Authentic gate authorization verification
        if not self._policy_gate.is_authorized(proposal, policy_decision):
            raise ExecutionBlockedError(
                "Execution rejected: decision was not authentically authorized by the trusted PolicyGate"
            )

        action_id = f"exec_{proposal.action_type.value}_{proposal.product_id}_{proposal.correlation_id[:8]}"
        self._executed_actions.append(action_id)

        return ExecutionResult(
            success=True,
            action_id=action_id,
            details={
                "product_id": proposal.product_id,
                "category": proposal.category,
                "quantity": str(proposal.quantity),
                "total": str(proposal.total),
                "currency": proposal.currency,
            },
            correlation_id=proposal.correlation_id,
        )