"""Agent reasoning and structured commerce action proposal layer."""

from decimal import Decimal
from enum import Enum
import hashlib
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ActionType(str, Enum):
    """Supported commercial actions for autonomous agents."""

    PURCHASE = "PURCHASE"


class ActionProposal(BaseModel):
    """Structured commerce action proposed by an agent.

    SECURITY INVARIANT:
    - Represents agent intent/proposal ONLY.
    - An agent output is untrusted input to the Policy Gate.
    - Zero authorization authority.
    - Extra fields or caller-injected authorization flags are strictly forbidden.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_type: ActionType = Field(..., description="Proposed action type.")
    product_id: str = Field(..., min_length=1, description="Target product or service identifier.")
    category: str = Field(..., min_length=1, description="Product category (e.g., 'laptop', 'accessory').")
    quantity: int = Field(..., gt=0, description="Quantity to purchase (must be > 0).")
    unit_price: Decimal = Field(..., gt=Decimal("0.00"), description="Per-unit price (must be > 0.00).")
    total: Decimal = Field(..., gt=Decimal("0.00"), description="Total purchase price.")
    currency: str = Field(default="INR", min_length=3, max_length=3, description="Currency code (strictly INR).")
    correlation_id: str = Field(..., min_length=1, description="Correlation identifier for tracing.")

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        code = v.upper().strip()
        if code != "INR":
            raise ValueError(f"Unsupported currency '{v}'. Current gateway policy strictly supports 'INR'.")
        return code

    @model_validator(mode="after")
    def validate_total_matches_calculation(self) -> "ActionProposal":
        expected_total = self.quantity * self.unit_price
        if self.total != expected_total:
            raise ValueError(
                f"Total mismatch: declared total ({self.total}) does not equal "
                f"quantity ({self.quantity}) * unit_price ({self.unit_price}) = {expected_total}"
            )
        return self

    def compute_fingerprint(self) -> str:
        """Compute deterministic SHA-256 fingerprint over security-relevant fields."""
        canonical_repr = (
            f"{self.action_type.value}:"
            f"{self.product_id}:"
            f"{self.category.lower().strip()}:"
            f"{self.quantity}:"
            f"{self.unit_price}:"
            f"{self.total}:"
            f"{self.currency}:"
            f"{self.correlation_id}"
        )
        return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


class CommerceAgent:
    """Autonomous commerce reasoning agent.

    SECURITY INVARIANT:
    - Reasons over external context and produces structured proposals.
    - Zero tool execution capability; cannot authorize actions.
    """

    def __init__(self, agent_id: str = "sentinel_commerce_agent_v1") -> None:
        self.agent_id = agent_id

    def propose_purchase(
        self,
        product_id: str,
        category: str,
        quantity: int,
        unit_price: Decimal | str | int | float,
        correlation_id: str,
        currency: str = "INR",
    ) -> ActionProposal:
        """Construct an explicit ActionProposal for Policy Gate review."""
        parsed_unit_price = Decimal(str(unit_price))
        calculated_total = Decimal(quantity) * parsed_unit_price

        return ActionProposal(
            action_type=ActionType.PURCHASE,
            product_id=product_id,
            category=category,
            quantity=quantity,
            unit_price=parsed_unit_price,
            total=calculated_total,
            currency=currency,
            correlation_id=correlation_id,
        )