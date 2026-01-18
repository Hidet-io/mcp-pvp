"""TTL-based session store."""

import secrets
from datetime import datetime, timedelta, UTC
from typing import Dict

from mcp_pvp.errors import SessionExpiredError, SessionNotFoundError, TokenNotFoundError
from mcp_pvp.models import StoredPII, VaultSession
from mcp_pvp.utils import utc_now

class SessionStore:
    """In-memory TTL-based session store."""

    def __init__(self) -> None:
        """Initialize session store."""
        self._sessions: Dict[str, VaultSession] = {}

    def create_session(self, ttl_seconds: int = 3600) -> VaultSession:
        """
        Create a new vault session.

        Args:
            ttl_seconds: Time-to-live in seconds

        Returns:
            New VaultSession instance
        """
        session_id = f"vs_{secrets.token_urlsafe(16)}"
        expires_at = utc_now() + timedelta(seconds=ttl_seconds)

        session = VaultSession(
            session_id=session_id,
            expires_at=expires_at,
        )

        self._sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> VaultSession:
        """
        Get a vault session.

        Args:
            session_id: Session ID

        Returns:
            VaultSession instance

        Raises:
            SessionNotFoundError: If session not found
            SessionExpiredError: If session has expired
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFoundError(details={"session_id": session_id})

        if session.expires_at < utc_now():
            # Clean up expired session
            del self._sessions[session_id]
            raise SessionExpiredError(
                details={
                    "session_id": session_id,
                    "expired_at": session.expires_at.isoformat(),
                }
            )

        return session

    def close_session(self, session_id: str) -> None:
        """
        Close a vault session.

        Args:
            session_id: Session ID
        """
        self._sessions.pop(session_id, None)

    def store_pii(
        self,
        session_id: str,
        pii_type: str,
        value: str,
    ) -> StoredPII:
        """
        Store PII in a session.

        Args:
            session_id: Session ID
            pii_type: PII type
            value: Raw PII value

        Returns:
            StoredPII instance with generated ref

        Raises:
            SessionNotFoundError: If session not found or expired
        """
        session = self.get_session(session_id)

        ref = f"tkn_{secrets.token_urlsafe(12)}"
        stored = StoredPII(
            ref=ref,
            pii_type=pii_type,  # type: ignore
            value=value,
        )

        session.tokens[ref] = stored
        return stored

    def get_pii(self, session_id: str, ref: str) -> StoredPII:
        """
        Get PII from a session.

        Args:
            session_id: Session ID
            ref: Token reference

        Returns:
            StoredPII instance

        Raises:
            SessionNotFoundError: If session not found or expired
            TokenNotFoundError: If token not found in session
        """
        session = self.get_session(session_id)

        stored = session.tokens.get(ref)
        if stored is None:
            raise TokenNotFoundError(
                details={
                    "session_id": session_id,
                    "ref": ref,
                }
            )

        return stored

    def cleanup_expired(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        now = utc_now()
        expired = [
            sid for sid, session in self._sessions.items() if session.expires_at < now
        ]

        for sid in expired:
            del self._sessions[sid]

        return len(expired)
