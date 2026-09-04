"""Audit event data models for Sentinel pipeline correlation and traceability."""

from collections.abc import Mapping
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuditEventType(str, Enum):
    """Supported taxonomy of pipeline lifecycle audit events."""

    INGESTED = "INGESTED"
    INSPECTION_ROUTED = "INSPECTION_ROUTED"
    DETECTED = "DETECTED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    POLICY_DECIDED = "POLICY_DECIDED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_BLOCKED = "ACTION_BLOCKED"


class AuditEvent(BaseModel):
    """Immutable record representing a discrete pipeline lifecycle event.

    SECURITY INVARIANT:
    - Used strictly for observability and audit traceability.
    - Has ZERO authority over action execution or policy decisions.
    - Never stores raw untrusted content, secrets, or authorization tokens.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for the audit event.",
    )
    correlation_id: str = Field(
        ...,
        min_length=1,
        description="Pipeline correlation identifier binding all operations in a workflow.",
    )
    event_type: AuditEventType = Field(
        ...,
        description="Lifecycle milestone type.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the event was recorded.",
    )
    details: Mapping[str, str] = Field(
        default_factory=lambda: MappingProxyType({}),
        description="Immutable structured non-sensitive string key-value attributes.",
    )

    @field_validator("details", mode="plain")
    @classmethod
    def enforce_immutable_details(cls, v: object) -> MappingProxyType[str, str]:
        if v is None:
            return MappingProxyType({})
        if not isinstance(v, Mapping):
            raise TypeError(f"details must be a mapping, got {type(v).__name__}")
        copied: dict[str, str] = {}
        for key, val in v.items():
            if not isinstance(key, str) or not isinstance(val, str):
                raise TypeError("All keys and values in details must be strings")
            copied[key] = val
        return MappingProxyType(copied)