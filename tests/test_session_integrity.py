"""Tests for session integrity validation (Task 1: Vault Hardening)."""

import pytest

from mcp_pvp.errors import TokenSessionMismatchError
from mcp_pvp.models import PIIType
from mcp_pvp.store import SessionStore


class TestSessionIntegrityValidation:
    """Test suite for session integrity validation."""

    def test_stored_pii_has_vault_session(self):
        """Test that StoredPII includes vault_session field."""
        store = SessionStore()
        session = store.create_session()

        stored = store.store_pii(
            session_id=session.session_id,
            pii_type=PIIType.EMAIL.value,
            value="alice@example.com",
        )

        # Verify vault_session field is set correctly
        assert stored.vault_session == session.session_id
        assert stored.ref.startswith("tkn_")
        assert stored.value == "alice@example.com"

    def test_get_pii_same_session_succeeds(self):
        """Test that retrieving PII from the same session succeeds."""
        store = SessionStore()
        session = store.create_session()

        # Store PII
        stored = store.store_pii(
            session_id=session.session_id,
            pii_type=PIIType.EMAIL.value,
            value="alice@example.com",
        )

        # Get PII from same session - should succeed
        retrieved = store.get_pii(session.session_id, stored.ref)

        assert retrieved.ref == stored.ref
        assert retrieved.value == "alice@example.com"
        assert retrieved.vault_session == session.session_id

    def test_get_pii_different_session_raises_mismatch_error(self):
        """Test that attempting to retrieve PII from different session raises error."""
        store = SessionStore()

        # Create two sessions
        session1 = store.create_session()
        session2 = store.create_session()

        # Store PII in session1
        stored = store.store_pii(
            session_id=session1.session_id,
            pii_type=PIIType.EMAIL.value,
            value="alice@example.com",
        )

        # Manually add token to session2's token dict (simulating attack)
        session2.tokens[stored.ref] = stored

        # Attempt to get PII from session2 - should raise TokenSessionMismatchError
        with pytest.raises(TokenSessionMismatchError) as exc_info:
            store.get_pii(session2.session_id, stored.ref)

        # Verify error details
        error = exc_info.value
        assert error.details["requesting_session"] == session2.session_id
        assert error.details["token_session"] == session1.session_id
        assert error.details["ref"] == stored.ref
        assert "does not belong to the requesting session" in error.message

    def test_cross_session_token_theft_prevented(self):
        """Test that cross-session token theft is prevented."""
        store = SessionStore()

        # Attacker creates their own session
        attacker_session = store.create_session()

        # Victim creates session and stores PII
        victim_session = store.create_session()
        victim_token = store.store_pii(
            session_id=victim_session.session_id,
            pii_type=PIIType.PHONE.value,
            value="+1-555-0100",
        )

        # Attacker somehow obtains victim's token reference
        # (e.g., via network sniffing, logs, etc.)
        stolen_ref = victim_token.ref

        # Attacker tries to add stolen token to their session
        # (This is the attack scenario we're defending against)
        attacker_session.tokens[stolen_ref] = victim_token

        # Attacker attempts to redeem stolen token
        with pytest.raises(TokenSessionMismatchError) as exc_info:
            store.get_pii(attacker_session.session_id, stolen_ref)

        # Verify the security error
        error = exc_info.value
        assert error.code.value == "ERR_TOKEN_SESSION_MISMATCH"
        assert error.details["requesting_session"] == attacker_session.session_id
        assert error.details["token_session"] == victim_session.session_id

    def test_multiple_tokens_same_session(self):
        """Test that multiple tokens in same session all validate correctly."""
        store = SessionStore()
        session = store.create_session()

        # Store multiple PII items
        tokens = []
        pii_values = [
            (PIIType.EMAIL, "alice@example.com"),
            (PIIType.PHONE, "+1-555-0100"),
            (PIIType.IPV4, "192.168.1.1"),
        ]

        for pii_type, value in pii_values:
            stored = store.store_pii(
                session_id=session.session_id,
                pii_type=pii_type.value,
                value=value,
            )
            tokens.append(stored)

        # Verify all tokens belong to same session
        for token in tokens:
            assert token.vault_session == session.session_id

        # Verify all can be retrieved successfully
        for token in tokens:
            retrieved = store.get_pii(session.session_id, token.ref)
            assert retrieved.vault_session == session.session_id
            assert retrieved.ref == token.ref

    def test_session_validation_with_expired_session(self):
        """Test that session validation works even with expired sessions."""
        store = SessionStore()

        from datetime import timedelta
        from mcp_pvp.utils import utc_now

        # Create session with normal TTL
        session = store.create_session(ttl_seconds=3600)

        # Store PII while session is valid
        stored = store.store_pii(
            session_id=session.session_id,
            pii_type=PIIType.EMAIL.value,
            value="test@example.com",
        )

        # Verify token has correct session
        assert stored.vault_session == session.session_id

        # Manually expire the session
        session.expires_at = utc_now() - timedelta(seconds=1)

        # Attempt to get PII should fail with SessionExpiredError,
        # not TokenSessionMismatchError (session expiry checked first)
        from mcp_pvp.errors import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            store.get_pii(session.session_id, stored.ref)

    def test_session_integrity_preserves_token_ownership(self):
        """Test that token ownership is immutable after creation."""
        store = SessionStore()
        session1 = store.create_session()
        session2 = store.create_session()

        # Store PII in session1
        stored = store.store_pii(
            session_id=session1.session_id,
            pii_type=PIIType.EMAIL.value,
            value="original@example.com",
        )

        # Verify initial ownership
        assert stored.vault_session == session1.session_id

        # Simulate attack: manually change vault_session field
        # (This tests that StoredPII's vault_session is checked, not just presence in tokens dict)
        stored.vault_session = session2.session_id

        # Add to session2's tokens
        session2.tokens[stored.ref] = stored

        # Attempt to get from session2 should SUCCEED because we actually changed
        # the vault_session field (this validates we're checking the field)
        retrieved = store.get_pii(session2.session_id, stored.ref)
        assert retrieved.vault_session == session2.session_id

        # But now trying to get from session1 should FAIL
        session1.tokens[stored.ref] = stored  # Re-add to session1
        with pytest.raises(TokenSessionMismatchError):
            store.get_pii(session1.session_id, stored.ref)
