"""Probabilistic ML prompt-injection detector wrapping protectai/deberta-v3-base-prompt-injection-v2."""

from collections.abc import Mapping
from typing import Any
import torch

from sentinel.detection.models import (
    LOCKED_MODEL_NAME,
    LOCKED_THRESHOLD,
    DetectionLabel,
    DetectionResult,
)


class PromptInjectionDetector:
    """Detects prompt injection using protectai/deberta-v3-base-prompt-injection-v2.

    SECURITY INVARIANT:
    - Answers: 'How likely is this content to be a prompt injection under the locked model?'
    - Outputs probabilistic evidence only.
    - Never authorizes consequential actions or evaluates spending rules.
    - Fail-closed: Model/tokenizer inference errors propagate as exceptions;
      they are NEVER masked as 'SAFE'.
    """

    def __init__(
        self,
        model_name: str = LOCKED_MODEL_NAME,
        device: str | None = None,
        tokenizer: Any | None = None,
        model: Any | None = None,
    ) -> None:
        if model_name != LOCKED_MODEL_NAME:
            raise ValueError(f"Detector model is permanently locked to '{LOCKED_MODEL_NAME}'")

        self.model_name = model_name
        self.threshold = LOCKED_THRESHOLD

        if device is not None:
            self.device = torch.device(device)
        else:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self._tokenizer = tokenizer
        self._model = model
        self._injection_label_idx: int | None = None

        if self._model is not None:
            if hasattr(self._model, "eval"):
                self._model.eval()
            self._resolve_injection_index()

    def _ensure_loaded(self) -> None:
        """Lazy-load the tokenizer and classification model once."""
        if self._tokenizer is None or self._model is None:
            try:
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self._model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name
                ).to(self.device)
                self._model.eval()
            except Exception as e:
                raise RuntimeError(
                    f"Failed to load detection model '{self.model_name}': {e}"
                ) from e

            self._resolve_injection_index()

    def _resolve_injection_index(self) -> None:
        """Determine which output logit index corresponds to INJECTION.

        Fails closed with RuntimeError if id2label is missing or ambiguous.
        """
        config = getattr(self._model, "config", None)
        id2label = getattr(config, "id2label", None) if config else None

        if not isinstance(id2label, dict) or not id2label:
            raise RuntimeError(
                f"Model configuration lacks valid 'id2label' mapping for '{self.model_name}'"
            )

        matching_indices = [
            int(idx) for idx, label in id2label.items() if "inject" in str(label).lower()
        ]

        if len(matching_indices) != 1:
            raise RuntimeError(
                f"Cannot unambiguously resolve injection class index from id2label: {id2label}"
            )

        self._injection_label_idx = matching_indices[0]

    def detect(self, content: str | bytes) -> DetectionResult:
        """Evaluate text content and return probabilistic injection evidence.

        Fail-closed: Any inference/tokenization error will raise an exception rather
        than returning a false SAFE result.
        """
        if not isinstance(content, (str, bytes)):
            raise TypeError(f"content must be str or bytes, got {type(content).__name__}")

        if isinstance(content, bytes):
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as e:
                raise ValueError(f"Failed to decode bytes as UTF-8: {e}") from e
        else:
            text = content

        self._ensure_loaded()

        try:
            raw_inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=False,
            )

            # Support both transformers.BatchEncoding and standard PyTorch dicts
            if hasattr(raw_inputs, "to"):
                inputs = raw_inputs.to(self.device)
            elif isinstance(raw_inputs, Mapping):
                inputs = {
                    k: v.to(self.device) if hasattr(v, "to") else v
                    for k, v in raw_inputs.items()
                }
            else:
                inputs = raw_inputs

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits[0]

            if self._injection_label_idx is None:
                raise RuntimeError("Injection label index was not resolved")

            if self._injection_label_idx < 0 or self._injection_label_idx >= logits.shape[-1]:
                raise RuntimeError(
                    f"Resolved injection index {self._injection_label_idx} is out of bounds for logits shape {logits.shape}"
                )

            probabilities = torch.softmax(logits, dim=-1)
            score = float(probabilities[self._injection_label_idx].item())
            score = max(0.0, min(1.0, score))

            label = (
                DetectionLabel.INJECTION
                if score >= self.threshold
                else DetectionLabel.SAFE
            )

            return DetectionResult(
                label=label,
                score=score,
                threshold=self.threshold,
                model_name=self.model_name,
            )
        except Exception as e:
            raise RuntimeError(f"Detector inference failure: {e}") from e