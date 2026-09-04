"""In-memory audit logger for tracing pipeline operations by correlation ID."""

from sentinel.audit.events import AuditEvent


class AuditLogger:
    """Stores and retrieves lifecycle audit events in memory.

    SECURITY INVARIANT:
    This logger is purely an observability sink. It carries NO authorization
    authority and does not influence Policy Gate or Action Executor outcomes.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def log(self, event: AuditEvent) -> AuditEvent:
        """Record an audit event while preserving chronological order."""
        if not isinstance(event, AuditEvent):
            raise TypeError(f"event must be an AuditEvent instance, got {type(event).__name__}")
        self._events.append(event)
        return event

    def get_by_correlation_id(self, correlation_id: str) -> list[AuditEvent]:
        """Return all audit events associated with the given correlation ID in insertion order."""
        return [evt for evt in self._events if evt.correlation_id == correlation_id]

    def get_all(self) -> list[AuditEvent]:
        """Return a shallow copy of all stored audit events."""
        return list(self._events)

    def clear(self) -> None:
        """Reset the in-memory audit log store."""
        self._events.clear()