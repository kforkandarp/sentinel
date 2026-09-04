"""Deterministic inspection router determining pre-inspection workflows."""

from sentinel.hashing import compute_artifact_hash
from sentinel.inspection.cache import InspectionCache
from sentinel.inspection.models import InspectionDecision, InspectionRoute
from sentinel.provenance import ProvenanceContext

# Default maximum raw payload length for cheap pre-inspection rejection (e.g. 5 MB)
DEFAULT_MAX_CONTENT_BYTES = 5 * 1024 * 1024


class InspectionRouter:
    """Evaluates incoming content and trusted provenance to assign an inspection route.

    Precedence:
    1. Deterministic Cheap BLOCK checks (e.g. empty content, size limits).
    2. Content-to-Provenance Hash Integrity Verification.
    3. Provenance-scoped Cache Lookup (CACHE_REUSE).
    4. Normal inspection path (DEEP_INSPECT).

    SECURITY INVARIANT:
    This router makes workflow cost decisions ONLY. It is not an authorization engine,
    not an ML detector, and does not determine action safety.
    """

    def __init__(
        self,
        cache: InspectionCache | None = None,
        max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
    ) -> None:
        if max_content_bytes <= 0:
            raise ValueError(f"max_content_bytes must be strictly greater than 0, got {max_content_bytes}")

        self._cache = cache if cache is not None else InspectionCache()
        self._max_content_bytes = max_content_bytes

    @property
    def cache(self) -> InspectionCache:
        return self._cache

    def route(
        self,
        content: str | bytes,
        provenance: ProvenanceContext,
    ) -> InspectionDecision:
        """Determine whether content should be blocked, reused from cache, or deeply inspected."""
        if not isinstance(content, (str, bytes)):
            raise TypeError(f"content must be str or bytes, got {type(content).__name__}")

        if not isinstance(provenance, ProvenanceContext):
            raise TypeError("provenance must be a valid trusted ProvenanceContext instance")

        content_bytes = content.encode("utf-8") if isinstance(content, str) else content

        # Rule 1 — Deterministic cheap BLOCK conditions
        if len(content_bytes) == 0 or content_bytes.isspace():
            return InspectionDecision(
                route=InspectionRoute.BLOCK,
                reason="Pre-inspection rejection: content payload is empty or whitespace-only",
            )

        if len(content_bytes) > self._max_content_bytes:
            return InspectionDecision(
                route=InspectionRoute.BLOCK,
                reason=(
                    f"Pre-inspection rejection: content payload exceeds size limit "
                    f"({len(content_bytes)} > {self._max_content_bytes} bytes)"
                ),
            )

        # Content <-> Provenance binding check (fail closed on mismatch)
        computed_hash = compute_artifact_hash(content_bytes)
        if computed_hash != provenance.artifact_hash:
            raise ValueError(
                f"Content integrity violation: computed content hash ({computed_hash}) "
                f"does not match provenance.artifact_hash ({provenance.artifact_hash})"
            )

        # Rule 2 — Provenance-scoped cache lookup
        cached_entry = self._cache.get(provenance)
        if cached_entry is not None:
            return InspectionDecision(
                route=InspectionRoute.CACHE_REUSE,
                reason="Valid prior inspection result found for identical content in this provenance scope",
                cached_result=cached_entry,
            )

        # Rule 3 — Normal inspection path
        return InspectionDecision(
            route=InspectionRoute.DEEP_INSPECT,
            reason="Uncached content assigned to standard deep inspection pipeline",
        )