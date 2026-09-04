"""Provenance-scoped in-memory cache for inspection workflow optimization."""

from collections.abc import Mapping
from sentinel.inspection.models import CachedInspectionResult
from sentinel.provenance import ProvenanceContext


class InspectionCache:
    """In-memory cache scoped by content hash and provenance identity.

    SECURITY INVARIANT:
    - Keying combines artifact_hash with source_type, source_id, and workflow.
    - Content hash alone is NEVER sufficient for cache identity.
    - A cache hit merely bypasses deep inspection; it NEVER authorizes consequential actions.
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, str, str, str], CachedInspectionResult] = {}

    @staticmethod
    def _build_key(provenance: ProvenanceContext) -> tuple[str, str, str, str]:
        """Construct a provenance-scoped composite cache key."""
        return (
            provenance.source_type,
            provenance.source_id,
            provenance.workflow,
            provenance.artifact_hash,
        )

    def get(self, provenance: ProvenanceContext) -> CachedInspectionResult | None:
        """Retrieve a cached inspection record matching the exact provenance scope."""
        key = self._build_key(provenance)
        return self._store.get(key)

    def put(
        self,
        provenance: ProvenanceContext,
        inspection_metadata: Mapping[str, str] | None = None,
    ) -> CachedInspectionResult:
        """Store an inspection record bound to the provenance context."""
        key = self._build_key(provenance)
        record = CachedInspectionResult(
            artifact_hash=provenance.artifact_hash,
            source_type=provenance.source_type,
            source_id=provenance.source_id,
            workflow=provenance.workflow,
            inspection_metadata=dict(inspection_metadata) if inspection_metadata is not None else {},
        )
        self._store[key] = record
        return record

    def clear(self) -> None:
        """Reset the internal cache store."""
        self._store.clear()