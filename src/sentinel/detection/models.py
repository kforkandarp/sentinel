"""Data models for probabilistic prompt-injection detection evidence."""

from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, field_validator

LOCKED_MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"
LOCKED_THRESHOLD = 0.5


class DetectionLabel(str, Enum):
    """Classification label produced by the prompt injection detector."""

    SAFE = "SAFE"
    INJECTION = "INJECTION"


class DetectionResult(BaseModel):
    """Probabilistic evidence returned by the detector.

    SECURITY INVARIANT:
    This model contains probabilistic classification evidence only.
    It does NOT grant action authorization, permission to execute, or safety clearance.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        protected_namespaces=(),
    )

    label: DetectionLabel = Field(
        ..., description="Probabilistic classification: SAFE or INJECTION."
    )
    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Probability/confidence score that content contains prompt injection.",
    )
    threshold: float = Field(
        default=LOCKED_THRESHOLD,
        description="Locked decision boundary threshold (0.5).",
    )
    model_name: str = Field(
        default=LOCKED_MODEL_NAME,
        description="Locked Hugging Face model identifier.",
    )

    @field_validator("threshold")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        if v != LOCKED_THRESHOLD:
            raise ValueError(f"Detector threshold is locked to {LOCKED_THRESHOLD}, got {v}")
        return v

    @field_validator("model_name")
    @classmethod
    def validate_model_name(cls, v: str) -> str:
        if v != LOCKED_MODEL_NAME:
            raise ValueError(f"Model name is locked to '{LOCKED_MODEL_NAME}', got '{v}'")
        return v