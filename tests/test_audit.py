"""Tests for Phase 6 Audit Logging and Correlation Invariants."""

import uuid
import pytest
from pydantic import ValidationError

from sentinel.audit.events import AuditEvent, AuditEventType
from sentinel.audit.logger import AuditLogger


def test_audit_event_creation_and_defaults():
    """Verify valid AuditEvent creation with default ID and UTC timestamp."""
    cid = str(uuid.uuid4())
    event = AuditEvent(
        correlation_id=cid,
        event_type=AuditEventType.INGESTED,
        details={"source_type": "direct", "workflow": "public_api"},
    )

    assert event.correlation_id == cid
    assert event.event_type == AuditEventType.INGESTED
    assert event.details["source_type"] == "direct"
    assert event.event_id is not None
    assert event.timestamp.tzinfo is not None


def test_audit_event_rejects_extra_fields():
    """Security Invariant: Extra fields (especially authorization flags) are strictly forbidden."""
    cid = str(uuid.uuid4())
    with pytest.raises(ValidationError):
        AuditEvent(
            correlation_id=cid,
            event_type=AuditEventType.POLICY_DECIDED,
            is_authorized=True,  # type: ignore
        )


def test_audit_event_immutability():
    """Verify audit events cannot be mutated after creation."""
    cid = str(uuid.uuid4())
    event = AuditEvent(
        correlation_id=cid,
        event_type=AuditEventType.DETECTED,
        details={"label": "SAFE"},
    )
    with pytest.raises(ValidationError):
        event.event_type = AuditEventType.ACTION_EXECUTED  # type: ignore


def test_audit_event_details_are_immutable():
    """Verify underlying details mapping is immutable and rejects item assignment."""
    cid = str(uuid.uuid4())
    event = AuditEvent(
        correlation_id=cid,
        event_type=AuditEventType.INGESTED,
        details={"key": "original"},
    )
    with pytest.raises(TypeError):
        event.details["key"] = "mutated"  # type: ignore

    with pytest.raises(TypeError):
        event.details["new_key"] = "value"  # type: ignore


def test_audit_event_contains_no_authorization_fields():
    """Security Invariant: AuditEvent model schema must not contain authorization or verdict fields."""
    forbidden_fields = {
        "is_safe",
        "safe",
        "is_authorized",
        "authorized",
        "allow",
        "deny",
        "policy_verdict",
        "auth_token",
        "audit_verified",
        "audit_status",
    }
    event_fields = set(AuditEvent.model_fields.keys())
    assert not forbidden_fields.intersection(event_fields)


def test_audit_logger_preserves_chronological_order():
    """Verify logger records events in exact chronological insertion order."""
    logger = AuditLogger()
    cid = str(uuid.uuid4())

    stages = [
        AuditEventType.INGESTED,
        AuditEventType.INSPECTION_ROUTED,
        AuditEventType.DETECTED,
        AuditEventType.ACTION_PROPOSED,
        AuditEventType.POLICY_DECIDED,
        AuditEventType.ACTION_EXECUTED,
    ]

    for stage in stages:
        logger.log(AuditEvent(correlation_id=cid, event_type=stage))

    retrieved = logger.get_by_correlation_id(cid)
    assert len(retrieved) == len(stages)
    assert [evt.event_type for evt in retrieved] == stages


def test_audit_logger_isolates_different_correlation_ids():
    """Verify events from distinct workflows are isolated and do not bleed together."""
    logger = AuditLogger()
    cid_1 = str(uuid.uuid4())
    cid_2 = str(uuid.uuid4())

    logger.log(AuditEvent(correlation_id=cid_1, event_type=AuditEventType.INGESTED))
    logger.log(AuditEvent(correlation_id=cid_2, event_type=AuditEventType.INGESTED))
    logger.log(AuditEvent(correlation_id=cid_1, event_type=AuditEventType.DETECTED))

    events_1 = logger.get_by_correlation_id(cid_1)
    events_2 = logger.get_by_correlation_id(cid_2)

    assert len(events_1) == 2
    assert [e.event_type for e in events_1] == [AuditEventType.INGESTED, AuditEventType.DETECTED]

    assert len(events_2) == 1
    assert [e.event_type for e in events_2] == [AuditEventType.INGESTED]


def test_audit_logger_get_all_returns_isolated_copy():
    """Verify get_all() returns a shallow copy that cannot mutate internal store."""
    logger = AuditLogger()
    cid = str(uuid.uuid4())
    logger.log(AuditEvent(correlation_id=cid, event_type=AuditEventType.INGESTED))

    all_events = logger.get_all()
    all_events.clear()

    assert len(logger.get_all()) == 1


def test_audit_logger_clear():
    """Verify clear() empties the store."""
    logger = AuditLogger()
    cid = str(uuid.uuid4())
    logger.log(AuditEvent(correlation_id=cid, event_type=AuditEventType.INGESTED))
    assert len(logger.get_all()) == 1

    logger.clear()
    assert len(logger.get_all()) == 0
    assert len(logger.get_by_correlation_id(cid)) == 0