"""Audit logging for PVP operations."""

import secrets
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel, Field

from mcp_pvp.models import PIIType, RunContext


class AuditEventType(str, Enum):
    """Types of audit events."""

    TOKENIZE = "TOKENIZE"
    RESOLVE = "RESOLVE"
    DELIVER = "DELIVER"
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_CLOSED = "SESSION_CLOSED"
    POLICY_DENIED = "POLICY_DENIED"
    CAPABILITY_INVALID = "CAPABILITY_INVALID"


def utc_now() -> datetime:
    """Get current UTC time."""
    return datetime.now(UTC)


class AuditEvent(BaseModel):
    """Audit event record."""

    audit_id: str = Field(default_factory=lambda: f"aud_{secrets.token_urlsafe(12)}")
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: AuditEventType
    vault_session: str | None = None
    run: RunContext | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    # NEVER include raw PII values
    # Only include: counts, types, sink names, ref IDs, etc.


class AuditLogger(ABC):
    """Abstract audit logger interface."""

    @abstractmethod
    def log_event(self, event: AuditEvent) -> None:
        """
        Log an audit event.

        Args:
            event: AuditEvent to log
        """
        pass

    @abstractmethod
    def get_events(
        self,
        vault_session: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        Query audit events.

        Args:
            vault_session: Filter by vault session (optional)
            event_type: Filter by event type (optional)
            limit: Maximum number of events to return

        Returns:
            List of AuditEvent instances
        """
        pass


class InMemoryAuditLogger(AuditLogger):
    """In-memory audit logger implementation."""

    def __init__(self) -> None:
        """Initialize in-memory audit logger."""
        self._events: list[AuditEvent] = []
        self.logger = structlog.get_logger(__name__)

    def log_event(self, event: AuditEvent) -> None:
        """
        Log an audit event.

        Args:
            event: AuditEvent to log
        """
        self._events.append(event)

        # Also log to structured logger
        self.logger.info(
            "audit_event",
            audit_id=event.audit_id,
            event_type=event.event_type.value,
            vault_session=event.vault_session,
            workflow_run_id=event.run.workflow_run_id if event.run else None,
            step_id=event.run.step_id if event.run else None,
            **event.details,
        )

    def get_events(
        self,
        vault_session: str | None = None,
        event_type: AuditEventType | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """
        Query audit events.

        Args:
            vault_session: Filter by vault session (optional)
            event_type: Filter by event type (optional)
            limit: Maximum number of events to return

        Returns:
            List of AuditEvent instances
        """
        filtered = self._events

        if vault_session is not None:
            filtered = [e for e in filtered if e.vault_session == vault_session]

        if event_type is not None:
            filtered = [e for e in filtered if e.event_type == event_type]

        # Return most recent first
        filtered = sorted(filtered, key=lambda e: e.timestamp, reverse=True)

        return filtered[:limit]


def create_tokenize_event(
    vault_session: str,
    run: RunContext | None,
    detections: int,
    tokens_created: int,
    types: dict[PIIType, int],
) -> AuditEvent:
    """Create a TOKENIZE audit event."""
    return AuditEvent(
        event_type=AuditEventType.TOKENIZE,
        vault_session=vault_session,
        run=run,
        details={
            "detections": detections,
            "tokens_created": tokens_created,
            "types": {k.value: v for k, v in types.items()},
        },
    )


def create_resolve_event(
    vault_session: str,
    run: RunContext | None,
    sink_kind: str,
    sink_name: str,
    disclosed: dict[PIIType, int],
) -> AuditEvent:
    """Create a RESOLVE audit event."""
    return AuditEvent(
        event_type=AuditEventType.RESOLVE,
        vault_session=vault_session,
        run=run,
        details={
            "sink_kind": sink_kind,
            "sink_name": sink_name,
            "disclosed": {k.value: v for k, v in disclosed.items()},
        },
    )


def create_deliver_event(
    vault_session: str,
    run: RunContext | None,
    tool_name: str,
    disclosed: dict[PIIType, int],
) -> AuditEvent:
    """Create a DELIVER audit event."""
    return AuditEvent(
        event_type=AuditEventType.DELIVER,
        vault_session=vault_session,
        run=run,
        details={
            "tool_name": tool_name,
            "disclosed": {k.value: v for k, v in disclosed.items()},
        },
    )


def create_policy_denied_event(
    vault_session: str | None,
    run: RunContext | None,
    pii_type: PIIType,
    sink_kind: str,
    sink_name: str,
    reason: str,
) -> AuditEvent:
    """Create a POLICY_DENIED audit event."""
    return AuditEvent(
        event_type=AuditEventType.POLICY_DENIED,
        vault_session=vault_session,
        run=run,
        details={
            "pii_type": pii_type.value,
            "sink_kind": sink_kind,
            "sink_name": sink_name,
            "reason": reason,
        },
    )
