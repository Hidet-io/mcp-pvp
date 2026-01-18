"""Tests for session store."""

from datetime import datetime, timedelta

import pytest
from freezegun import freeze_time

from mcp_pvp.errors import SessionExpiredError, SessionNotFoundError, TokenNotFoundError
from mcp_pvp.models import PIIType
from mcp_pvp.store import SessionStore


def test_create_session(session_store: SessionStore) -> None:
    """Test session creation."""
    session = session_store.create_session(ttl_seconds=3600)

    assert session.session_id.startswith("vs_")
    assert len(session.tokens) == 0
    assert session.disclosed_count == 0
    assert session.disclosed_bytes == 0


def test_get_session_success(session_store: SessionStore) -> None:
    """Test getting an existing session."""
    created = session_store.create_session()
    retrieved = session_store.get_session(created.session_id)

    assert retrieved.session_id == created.session_id
    assert retrieved.expires_at == created.expires_at


def test_get_session_not_found(session_store: SessionStore) -> None:
    """Test getting a non-existent session."""
    with pytest.raises(SessionNotFoundError):
        session_store.get_session("vs_nonexistent")


def test_get_session_expired(session_store: SessionStore) -> None:
    """Test getting an expired session."""
    with freeze_time("2024-01-01 12:00:00"):
        session = session_store.create_session(ttl_seconds=3600)
        session_id = session.session_id

    # Move time forward past expiration
    with freeze_time("2024-01-01 14:00:00"):  # 2 hours later
        with pytest.raises(SessionExpiredError):
            session_store.get_session(session_id)


def test_close_session(session_store: SessionStore) -> None:
    """Test closing a session."""
    session = session_store.create_session()
    session_id = session.session_id

    session_store.close_session(session_id)

    with pytest.raises(SessionNotFoundError):
        session_store.get_session(session_id)


def test_store_pii(session_store: SessionStore) -> None:
    """Test storing PII in a session."""
    session = session_store.create_session()

    stored = session_store.store_pii(
        session_id=session.session_id,
        pii_type=PIIType.EMAIL.value,
        value="test@example.com",
    )

    assert stored.ref.startswith("tkn_")
    assert stored.pii_type == PIIType.EMAIL
    assert stored.value == "test@example.com"


def test_get_pii(session_store: SessionStore) -> None:
    """Test retrieving PII from a session."""
    session = session_store.create_session()

    stored = session_store.store_pii(
        session_id=session.session_id,
        pii_type=PIIType.EMAIL.value,
        value="test@example.com",
    )

    retrieved = session_store.get_pii(session.session_id, stored.ref)

    assert retrieved.ref == stored.ref
    assert retrieved.value == "test@example.com"


def test_get_pii_not_found(session_store: SessionStore) -> None:
    """Test getting non-existent PII."""
    session = session_store.create_session()

    with pytest.raises(TokenNotFoundError):
        session_store.get_pii(session.session_id, "tkn_nonexistent")


def test_cleanup_expired(session_store: SessionStore) -> None:
    """Test cleaning up expired sessions."""
    with freeze_time("2024-01-01 12:00:00"):
        s1 = session_store.create_session(ttl_seconds=3600)
        s2 = session_store.create_session(ttl_seconds=7200)

    # Move time forward to expire s1 but not s2
    with freeze_time("2024-01-01 13:30:00"):
        cleaned = session_store.cleanup_expired()

        assert cleaned == 1
        with pytest.raises(SessionNotFoundError):
            session_store.get_session(s1.session_id)

        # s2 should still exist
        session_store.get_session(s2.session_id)
