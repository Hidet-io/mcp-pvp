"""Tests for result tokenization in same session (Task 2: Vault Hardening)."""

import pytest

from mcp_pvp.executor import ToolExecutor
from mcp_pvp.models import (
    DeliverRequest,
    PIIType,
    Policy,
    PolicyAllow,
    SinkPolicy,
    TokenFormat,
    TokenizeRequest,
    ToolCall,
)
from mcp_pvp.vault import Vault


class EchoExecutor(ToolExecutor):
    """Test executor that echoes PII back in results."""

    async def execute(self, tool_name: str, injected_args: dict) -> dict:
        """Echo the email back in the result."""
        email = injected_args.get("email", "unknown")
        return {
            "status": "success",
            "message": f"Sent notification to {email}",
            "recipient": email,
        }

    async def list_tools(self) -> list[str]:
        return []

    async def get_tool_info(self, tool_name: str) -> dict:
        return {}

    async def get_tool(self, tool_name: str):
        return None


class GenerateNewPIIExecutor(ToolExecutor):
    """Test executor that generates NEW PII in results."""

    async def execute(self, tool_name: str, injected_args: dict) -> dict:
        """Generate a result with NEW email not in the original request."""
        return {
            "status": "success",
            "message": "Notification sent",
            "support_email": "support@example.com",  # NEW PII not in input
            "backup_contact": "backup@example.com",  # Another NEW PII
        }

    async def list_tools(self) -> list[str]:
        return []

    async def get_tool_info(self, tool_name: str) -> dict:
        return {}

    async def get_tool(self, tool_name: str):
        return None


class TestResultTokenizationSameSession:
    """Test suite for result tokenization in same session."""

    def test_tokenize_without_vault_session_creates_new_session(self):
        """Test that tokenize creates new session when vault_session not provided."""
        vault = Vault()

        # Tokenize without vault_session
        response1 = vault.tokenize(
            TokenizeRequest(
                content="Contact alice@example.com for details",
                token_format=TokenFormat.TEXT,
            )
        )

        response2 = vault.tokenize(
            TokenizeRequest(
                content="Contact bob@example.com for details",
                token_format=TokenFormat.TEXT,
            )
        )

        # Each call should create a new session
        assert response1.vault_session != response2.vault_session
        assert response1.vault_session.startswith("vs_")
        assert response2.vault_session.startswith("vs_")

    def test_tokenize_with_vault_session_reuses_existing_session(self):
        """Test that tokenize reuses session when vault_session is provided."""
        vault = Vault()

        # Create initial session
        response1 = vault.tokenize(
            TokenizeRequest(
                content="Contact alice@example.com",
                token_format=TokenFormat.TEXT,
            )
        )

        initial_session = response1.vault_session
        initial_token_count = len(response1.tokens)

        # Tokenize with existing vault_session
        response2 = vault.tokenize(
            TokenizeRequest(
                content="Also contact bob@example.com",
                token_format=TokenFormat.TEXT,
                vault_session=initial_session,  # Reuse session
            )
        )

        # Should return same session
        assert response2.vault_session == initial_session

        # Session should now have more tokens
        session = vault.store.get_session(initial_session)
        assert len(session.tokens) == initial_token_count + len(response2.tokens)

    @pytest.mark.asyncio
    async def test_deliver_result_tokens_belong_to_same_session(self):
        """Test that result tokenization reuses the deliver request's session."""
        policy = Policy(
            sinks={
                "tool:send_notification": SinkPolicy(
                    allow=[
                        PolicyAllow(type=PIIType.EMAIL, arg_paths=["email"]),
                    ]
                )
            }
        )

        vault = Vault(policy=policy, executor=EchoExecutor())

        # Tokenize initial content
        tokenize_response = vault.tokenize(
            TokenizeRequest(
                content="Send to alice@example.com",
                token_format=TokenFormat.JSON,
            )
        )

        original_session = tokenize_response.vault_session
        email_token = tokenize_response.tokens[0]

        # Deliver with token (tool result will contain PII and get tokenized)
        deliver_response = await vault.deliver(
            DeliverRequest(
                vault_session=original_session,
                tool_call=ToolCall(
                    name="send_notification",
                    args={"email": email_token.model_dump(by_alias=True)},
                ),
            )
        )

        # Result should be tokenized
        assert len(deliver_response.result_tokens) > 0

        # All result tokens should belong to the SAME session
        for result_token in deliver_response.result_tokens:
            stored = vault.store.get_pii(original_session, result_token.ref)
            assert stored.vault_session == original_session

    @pytest.mark.asyncio
    async def test_session_token_count_increases_with_result_tokenization(self):
        """Test that session token count increases when results are tokenized with NEW PII."""
        policy = Policy(
            sinks={
                "tool:send_email": SinkPolicy(
                    allow=[
                        PolicyAllow(type=PIIType.EMAIL, arg_paths=["to"]),
                    ]
                )
            }
        )

        # Use executor that generates NEW PII in results
        vault = Vault(policy=policy, executor=GenerateNewPIIExecutor())

        # Tokenize initial PII
        tokenize_response = vault.tokenize(
            TokenizeRequest(
                content="Email: alice@example.com",
                token_format=TokenFormat.JSON,
            )
        )

        session_id = tokenize_response.vault_session
        initial_token_count = len(vault.store.get_session(session_id).tokens)

        # Deliver (result will contain NEW PII that gets tokenized in same session)
        deliver_response = await vault.deliver(
            DeliverRequest(
                vault_session=session_id,
                tool_call=ToolCall(
                    name="send_email",
                    args={"to": tokenize_response.tokens[0].model_dump(by_alias=True)},
                ),
            )
        )

        # Result should contain new PII tokens
        assert len(deliver_response.result_tokens) > 0

        # Session should have more tokens now (original + result tokens)
        final_token_count = len(vault.store.get_session(session_id).tokens)
        assert final_token_count > initial_token_count

        # Verify all result tokens belong to the same session
        for result_token in deliver_response.result_tokens:
            stored = vault.store.get_pii(session_id, result_token.ref)
            assert stored.vault_session == session_id

    @pytest.mark.asyncio
    async def test_multi_round_deliver_maintains_single_session(self):
        """Test that multiple deliver calls can maintain a single session."""
        policy = Policy(
            sinks={
                "tool:process": SinkPolicy(
                    allow=[
                        PolicyAllow(type=PIIType.EMAIL, arg_paths=["data"]),
                    ]
                )
            }
        )

        vault = Vault(policy=policy, executor=EchoExecutor())

        # Initial tokenization
        tokenize_response = vault.tokenize(
            TokenizeRequest(
                content="Process alice@example.com",
                token_format=TokenFormat.JSON,
            )
        )

        session_id = tokenize_response.vault_session

        # First deliver
        await vault.deliver(
            DeliverRequest(
                vault_session=session_id,
                tool_call=ToolCall(
                    name="process",
                    args={"data": tokenize_response.tokens[0].model_dump(by_alias=True)},
                ),
            )
        )

        # Second deliver with a new manual tokenization in same session
        tokenize_response2 = vault.tokenize(
            TokenizeRequest(
                content="Also process bob@example.com",
                token_format=TokenFormat.JSON,
                vault_session=session_id,  # Reuse session
            )
        )

        # Should still be same session
        assert tokenize_response2.vault_session == session_id

        await vault.deliver(
            DeliverRequest(
                vault_session=session_id,
                tool_call=ToolCall(
                    name="process",
                    args={"data": tokenize_response2.tokens[0].model_dump(by_alias=True)},
                ),
            )
        )

        # All tokens should belong to single session
        session = vault.store.get_session(session_id)
        for token_ref in session.tokens:
            assert session.tokens[token_ref].vault_session == session_id

    @pytest.mark.asyncio
    async def test_result_token_session_mismatch_raises_error(self):
        """Test that result tokens are validated by session integrity checks."""
        policy = Policy(
            sinks={
                "tool:get_data": SinkPolicy(
                    allow=[
                        PolicyAllow(type=PIIType.EMAIL, arg_paths=["user"]),
                    ]
                )
            }
        )

        vault = Vault(policy=policy, executor=EchoExecutor())

        # Create session 1 and tokenize
        response1 = vault.tokenize(
            TokenizeRequest(
                content="User: alice@example.com",
                token_format=TokenFormat.JSON,
            )
        )
        session1 = response1.vault_session

        # Deliver and get result tokens in session 1
        deliver_response = await vault.deliver(
            DeliverRequest(
                vault_session=session1,
                tool_call=ToolCall(
                    name="get_data",
                    args={"user": response1.tokens[0].model_dump(by_alias=True)},
                ),
            )
        )

        result_tokens = deliver_response.result_tokens

        # Create a different session
        response2 = vault.tokenize(
            TokenizeRequest(
                content="Other user: bob@example.com",
                token_format=TokenFormat.JSON,
            )
        )
        session2 = response2.vault_session

        # Try to redeem result tokens from session1 using session2
        # This should fail due to session integrity validation
        from mcp_pvp.errors import TokenSessionMismatchError

        if result_tokens:
            result_token_ref = result_tokens[0].ref
            with pytest.raises(TokenSessionMismatchError):
                vault.store.get_pii(session2, result_token_ref)

    def test_session_reuse_with_expired_session_fails(self):
        """Test that attempting to reuse expired session raises error."""
        vault = Vault()

        # Create session with short TTL
        from datetime import timedelta

        from mcp_pvp.utils import utc_now

        response = vault.tokenize(
            TokenizeRequest(
                content="Test content with alice@example.com",
                token_format=TokenFormat.TEXT,
            )
        )

        session_id = response.vault_session

        # Manually expire the session
        session = vault.store.get_session(session_id)
        session.expires_at = utc_now() - timedelta(seconds=1)

        # Attempt to reuse expired session
        from mcp_pvp.errors import SessionExpiredError

        with pytest.raises(SessionExpiredError):
            vault.tokenize(
                TokenizeRequest(
                    content="More content with bob@example.com",
                    token_format=TokenFormat.TEXT,
                    vault_session=session_id,  # Try to reuse expired session
                )
            )
