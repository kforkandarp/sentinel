"""Comprehensive unit and security tests for Phase 2 Inspection Router and Cache."""

import pytest
from pydantic import ValidationError

from sentinel.inspection.cache import InspectionCache
from sentinel.inspection.models import (
    CachedInspectionResult,
    InspectionDecision,
    InspectionRoute,
)
from sentinel.inspection.router import InspectionRouter
from sentinel.provenance import create_trusted_provenance


def test_new_valid_content_routes_to_deep_inspect():
    """Verify standard new external content is routed to DEEP_INSPECT."""
    content = "Fresh product review: Seller was prompt and delivered goods."
    prov = create_trusted_provenance(
        content=content,
        source_type="direct",
        source_id="client:external_user_1",
        workflow="public_api",
    )
    router = InspectionRouter()

    decision = router.route(content, prov)

    assert decision.route == InspectionRoute.DEEP_INSPECT
    assert "deep inspection" in decision.reason
    assert decision.cached_result is None


def test_empty_content_triggers_hard_block():
    """Verify empty or whitespace-only content deterministically triggers BLOCK."""
    router = InspectionRouter()

    # Empty string
    prov_empty = create_trusted_provenance(
        content="",
        source_type="direct",
        source_id="client:test",
        workflow="public_api",
    )
    decision = router.route("", prov_empty)
    assert decision.route == InspectionRoute.BLOCK
    assert "empty" in decision.reason

    # Whitespace only
    prov_spaces = create_trusted_provenance(
        content="   \n\t  ",
        source_type="direct",
        source_id="client:test",
        workflow="public_api",
    )
    decision_spaces = router.route("   \n\t  ", prov_spaces)
    assert decision_spaces.route == InspectionRoute.BLOCK


def test_payload_exceeding_limit_triggers_hard_block():
    """Verify oversized content triggers deterministic cheap BLOCK without ML."""
    router = InspectionRouter(max_content_bytes=100)
    large_content = "X" * 101
    prov = create_trusted_provenance(
        content=large_content,
        source_type="direct",
        source_id="client:test",
        workflow="public_api",
    )

    decision = router.route(large_content, prov)
    assert decision.route == InspectionRoute.BLOCK
    assert "exceeds size limit" in decision.reason


def test_cache_hit_returns_cache_reuse():
    """Verify populated cache returns CACHE_REUSE for identical content and provenance."""
    content = "Catalog product listing details."
    prov = create_trusted_provenance(
        content=content,
        source_type="web",
        source_id="https://merchant.example.com/item/1",
        workflow="web_ingestion",
    )
    router = InspectionRouter()

    # Pre-populate cache with prior inspection result
    router.cache.put(prov, inspection_metadata={"prior_run": "clean_scan"})

    decision = router.route(content, prov)

    assert decision.route == InspectionRoute.CACHE_REUSE
    assert decision.cached_result is not None
    assert decision.cached_result.artifact_hash == prov.artifact_hash
    assert decision.cached_result.inspection_metadata["prior_run"] == "clean_scan"


def test_cache_miss_returns_deep_inspect():
    """Verify cache miss falls through to DEEP_INSPECT."""
    content = "Unseen document content."
    prov = create_trusted_provenance(
        content=content,
        source_type="document",
        source_id="doc_uuid_999",
        workflow="document_ingestion",
    )
    router = InspectionRouter()

    decision = router.route(content, prov)
    assert decision.route == InspectionRoute.DEEP_INSPECT


def test_provenance_scoping_prevents_cross_source_cache_reuse():
    """Security Invariant: Same content from different source_id must NOT hit cache."""
    content = "Quarterly supplier price agreement terms."

    prov_vendor_a = create_trusted_provenance(
        content=content,
        source_type="document",
        source_id="vendor_a_invoice",
        workflow="document_ingestion",
    )
    prov_vendor_b = create_trusted_provenance(
        content=content,
        source_type="document",
        source_id="vendor_b_invoice",
        workflow="document_ingestion",
    )

    router = InspectionRouter()
    router.cache.put(prov_vendor_a, inspection_metadata={"scanned_by": "node_1"})

    decision_a = router.route(content, prov_vendor_a)
    assert decision_a.route == InspectionRoute.CACHE_REUSE

    decision_b = router.route(content, prov_vendor_b)
    assert decision_b.route == InspectionRoute.DEEP_INSPECT
    assert decision_b.cached_result is None


def test_provenance_scoping_different_source_type_and_workflow():
    """Verify cache miss if source_type or workflow differ despite identical content."""
    content = "Standard return policy text."

    prov_direct = create_trusted_provenance(
        content=content,
        source_type="direct",
        source_id="origin_1",
        workflow="public_api",
    )
    prov_web = create_trusted_provenance(
        content=content,
        source_type="web",
        source_id="origin_1",
        workflow="web_ingestion",
    )

    router = InspectionRouter()
    router.cache.put(prov_direct)

    decision = router.route(content, prov_web)
    assert decision.route == InspectionRoute.DEEP_INSPECT


def test_different_artifact_instances_share_cache_if_provenance_and_hash_match():
    """Verify ephemeral artifact_id does not break legitimate caching when hash + provenance match."""
    content = "Repetitive order payload."
    prov_instance_1 = create_trusted_provenance(
        content=content,
        source_type="direct",
        source_id="client:persistent_agent",
        workflow="public_api",
    )
    prov_instance_2 = create_trusted_provenance(
        content=content,
        source_type="direct",
        source_id="client:persistent_agent",
        workflow="public_api",
    )

    assert prov_instance_1.artifact_id != prov_instance_2.artifact_id
    assert prov_instance_1.artifact_hash == prov_instance_2.artifact_hash

    router = InspectionRouter()
    router.cache.put(prov_instance_1)

    decision = router.route(content, prov_instance_2)
    assert decision.route == InspectionRoute.CACHE_REUSE


def test_router_rejects_mismatched_content_and_provenance_hash():
    """Regression test: Fail closed when content does not match provenance.artifact_hash."""
    content_a = "Original Content A that was previously inspected"
    prov_a = create_trusted_provenance(
        content=content_a,
        source_type="direct",
        source_id="client:test_user",
        workflow="public_api",
    )

    router = InspectionRouter()
    router.cache.put(prov_a, inspection_metadata={"status": "inspected"})

    content_b = "Malicious Content B trying to ride on Content A's provenance"
    with pytest.raises(ValueError, match="Content integrity violation"):
        router.route(content_b, prov_a)


def test_cached_metadata_mutation_isolation():
    """Regression test: Mutating input metadata dict does not mutate stored cache record."""
    content = "Immutable metadata check"
    prov = create_trusted_provenance(
        content=content,
        source_type="direct",
        source_id="client:test",
        workflow="public_api",
    )
    cache = InspectionCache()

    caller_metadata = {"scanner": "deberta_v3", "tag": "initial"}
    record = cache.put(prov, caller_metadata)

    caller_metadata["tag"] = "MUTATED_BY_CALLER"
    caller_metadata["injected_key"] = "ATTACK"

    retrieved = cache.get(prov)
    assert retrieved is not None
    assert retrieved.inspection_metadata["tag"] == "initial"
    assert "injected_key" not in retrieved.inspection_metadata
    assert record.inspection_metadata["tag"] == "initial"


def test_router_and_cache_models_contain_no_authorization_fields():
    """Security Boundary: Router and Cache models must not possess authorization or safety fields."""
    forbidden = {
        "is_safe",
        "safe",
        "is_authorized",
        "authorized",
        "allow",
        "deny",
        "policy_verdict",
        "verdict",
        "risk_score",
    }

    decision_fields = set(InspectionDecision.model_fields.keys())
    assert not forbidden.intersection(decision_fields)

    cached_fields = set(CachedInspectionResult.model_fields.keys())
    assert not forbidden.intersection(cached_fields)


def test_router_rejects_untrusted_raw_provenance_dict():
    """Verify router strictly enforces ProvenanceContext type boundary."""
    router = InspectionRouter()
    fake_provenance = {
        "source_type": "direct",
        "source_id": "test",
        "artifact_hash": "a" * 64,
        "is_safe": True,
    }

    with pytest.raises(TypeError, match="must be a valid trusted ProvenanceContext"):
        router.route("content", fake_provenance)  # type: ignore


def test_inspection_decision_is_immutable():
    """Verify that InspectionDecision instances are immutable and reject mutation."""
    decision = InspectionDecision(
        route=InspectionRoute.DEEP_INSPECT,
        reason="Initial assignment",
    )
    with pytest.raises(ValidationError):
        decision.route = InspectionRoute.BLOCK  # type: ignore


def test_inspection_router_init_rejects_non_positive_max_content_bytes():
    """Verify InspectionRouter rejects max_content_bytes <= 0."""
    with pytest.raises(ValueError, match="strictly greater than 0"):
        InspectionRouter(max_content_bytes=0)

    with pytest.raises(ValueError, match="strictly greater than 0"):
        InspectionRouter(max_content_bytes=-50)


def test_inspection_router_route_rejects_invalid_content_runtime_type():
    """Verify InspectionRouter.route rejects content types that are neither str nor bytes."""
    router = InspectionRouter()
    prov = create_trusted_provenance(
        content="test",
        source_type="direct",
        source_id="src_1",
        workflow="public_api",
    )

    with pytest.raises(TypeError, match="content must be str or bytes"):
        router.route(12345, prov)  # type: ignore

    with pytest.raises(TypeError, match="content must be str or bytes"):
        router.route({"raw_text": "hello"}, prov)  # type: ignore

    with pytest.raises(TypeError, match="content must be str or bytes"):
        router.route(["content"], prov)  # type: ignore


def test_inspection_decision_model_validator_invariants():
    """Verify route and cached_result invariant enforcement on InspectionDecision."""
    dummy_cached_result = CachedInspectionResult(
        artifact_hash="a" * 64,
        source_type="direct",
        source_id="src_1",
        workflow="public_api",
    )

    with pytest.raises(ValidationError, match="route 'CACHE_REUSE' requires cached_result to be non-None"):
        InspectionDecision(
            route=InspectionRoute.CACHE_REUSE,
            reason="Missing cached result",
            cached_result=None,
        )

    with pytest.raises(ValidationError, match="route 'BLOCK' requires cached_result to be None"):
        InspectionDecision(
            route=InspectionRoute.BLOCK,
            reason="Blocked content",
            cached_result=dummy_cached_result,
        )

    with pytest.raises(ValidationError, match="route 'DEEP_INSPECT' requires cached_result to be None"):
        InspectionDecision(
            route=InspectionRoute.DEEP_INSPECT,
            reason="Standard inspection path",
            cached_result=dummy_cached_result,
        )

    valid_cache_reuse = InspectionDecision(
        route=InspectionRoute.CACHE_REUSE,
        reason="Cache hit",
        cached_result=dummy_cached_result,
    )
    assert valid_cache_reuse.cached_result is not None

    valid_deep_inspect = InspectionDecision(
        route=InspectionRoute.DEEP_INSPECT,
        reason="Cache miss",
        cached_result=None,
    )
    assert valid_deep_inspect.cached_result is None

    valid_block = InspectionDecision(
        route=InspectionRoute.BLOCK,
        reason="Content blocked",
        cached_result=None,
    )
    assert valid_block.cached_result is None