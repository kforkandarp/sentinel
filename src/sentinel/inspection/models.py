"""Data models for inspection routing decisions and cached inspection records."""

from enum import Enum
from typing import Self
from pydantic import BaseModel, ConfigDict, Field, model_validator


class InspectionRoute(str, Enum):
    """The exclusive routing outcomes for content inspection workflow."""

    BLOCK = "BLOCK"
    CACHE_REUSE = "CACHE_REUSE"
    DEEP_INSPECT = "DEEP_INSPECT"


class CachedInspectionResult(BaseModel):
    """Minimal inspection record stored in the inspection cache.

    SECURITY INVARIANT:
    This contains prior inspection findings/metadata for inspection workflow optimization.
    It does NOT represent an authorization decision, safe verdict, or action permit.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_hash: str = Field(..., description="Deterministic content SHA-256 hash.")
    source_type: str = Field(..., description="Scoped source type.")
    source_id: str = Field(..., description="Scoped source identifier.")
    workflow: str = Field(..., description="Scoped intake workflow.")
    inspection_metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Inspection-layer diagnostic metadata.",
    )


class InspectionDecision(BaseModel):
    """The deterministic routing outcome determined by the Inspection Router.

    SECURITY INVARIANT:
    The routing decision determines only the inspection pipeline workflow.
    It does NOT grant action authorization, declare safety, or invoke the Policy Gate.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    route: InspectionRoute = Field(..., description="The selected inspection workflow route.")
    reason: str = Field(..., min_length=1, description="Deterministic explanation for the decision.")
    cached_result: CachedInspectionResult | None = Field(
        default=None,
        description="Cached inspection result when route is CACHE_REUSE; None otherwise.",
    )

    @model_validator(mode="after")
    def validate_route_cached_result_invariant(self) -> Self:
        """Enforce invariant binding between route type and cached_result presence."""
        if self.route == InspectionRoute.CACHE_REUSE and self.cached_result is None:
            raise ValueError("route 'CACHE_REUSE' requires cached_result to be non-None")
        if self.route in (InspectionRoute.BLOCK, InspectionRoute.DEEP_INSPECT) and self.cached_result is not None:
            raise ValueError(f"route '{self.route.value}' requires cached_result to be None")
        return self