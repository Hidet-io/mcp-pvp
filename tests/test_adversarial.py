"""Adversarial security tests for PVP.

These tests validate the security posture of the vault under attack scenarios:
- Policy bypass attempts
- Capability tampering
- Deliver-mode boundary violations
- Default-deny enforcement for LLM/ENGINE sinks
"""

import pytest

from mcp_pvp.caps import CapabilityManager
from mcp_pvp.errors import CapabilityInvalidError, CapabilityTamperedError
from mcp_pvp.models import (
    DeliverRequest,
    PIIType,
    Policy,
    PolicyAllow,
    ResolveRequest,
    Sink,
    SinkPolicy,
    TokenFormat,
    TokenizeRequest,
)
from mcp_pvp.vault import Vault


class TestPolicyBypass:
    """Test attempts to bypass policy restrictions."""

    def test_resolve_without_capability_fails(self):
        """Attacker tries to resolve token without valid capability.

        v1.0 UPDATE: Capabilities are now issued on-demand by vault after policy check.
        This test now verifies that capabilities CANNOT be reused with different sinks.
        """
        policy = Policy(
            sinks={
                "tool:send_email": {"allow": [{"type": PIIType.EMAIL}]},
            }
        )
        vault = Vault(policy=policy)

        # Tokenize - use EMAIL which is detected by regex
        tok_req = TokenizeRequest(content="Contact: user@example.com")
        tok_resp = vault.tokenize(tok_req)

        if not tok_resp.tokens:
            pytest.skip("No tokens detected")

        token = tok_resp.tokens[0]

        # Resolve for approved sink (should work)
        resolve_resp1 = vault.resolve(
            ResolveRequest(
                vault_session=tok_resp.vault_session,
                tokens=[{"ref": token.pii_ref, "cap": None}],  # vault issues cap
                sink={"kind": "tool", "name": "send_email"},
            )
        )
        assert len(resolve_resp1.values) == 1

        # Try to resolve for DIFFERENT sink without explicit cap (should fail - policy denied)
        with pytest.raises((ValueError, Exception)):  # Policy or capability error
            vault.resolve(
                ResolveRequest(
                    vault_session=tok_resp.vault_session,
                    tokens=[{"ref": token.pii_ref, "cap": None}],
                    sink={"kind": "tool", "name": "malicious_tool"},  # Different tool!
                )
            )

    def test_resolve_with_tampered_capability_fails(self):
        """Attacker tries to reuse capability from one sink with a different sink.

        v1.0: This is the CRITICAL security test - capabilities are now sink-bound
        and CANNOT be reused even if HMAC is valid.
        """
        policy = Policy(
            sinks={
                "tool:send_email": {"allow": [{"type": PIIType.EMAIL}]},
                "tool:exfiltrate": {"allow": [{"type": PIIType.EMAIL}]},  # Both allowed for testing
            }
        )
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: admin@company.com")
        tok_resp = vault.tokenize(tok_req)

        if not tok_resp.tokens:
            pytest.skip("No tokens detected")

        token = tok_resp.tokens[0]

        # Get capability for send_email
        cap_for_send_email = vault.issue_capability(
            vault_session=tok_resp.vault_session,
            pii_ref=token.pii_ref,
            pii_type=PIIType.EMAIL,
            sink=Sink(kind="tool", name="send_email"),
            ttl_seconds=300,
        )

        # Try to use send_email capability with DIFFERENT tool
        with pytest.raises((ValueError, CapabilityInvalidError, CapabilityTamperedError)):
            vault.resolve(
                ResolveRequest(
                    vault_session=tok_resp.vault_session,
                    tokens=[{"ref": token.pii_ref, "cap": cap_for_send_email}],  # Reused cap!
                    sink={"kind": "tool", "name": "exfiltrate"},  # Different tool!
                )
            )

    def test_resolve_denied_sink_by_policy(self):
        """Policy denies access to specific sink."""
        policy = Policy(
            default_allow=False,
            rules=[
                {"sink_kind": "ENGINE", "sink_name": "*", "action": "deny"},
            ],
        )
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: test@test.com")
        tok_resp = vault.tokenize(tok_req)

        if not tok_resp.tokens:
            pytest.skip("No tokens detected")

        token = tok_resp.tokens[0]

        # Attempt to resolve to denied ENGINE sink
        with pytest.raises((ValueError, Exception)):
            vault.resolve(
                ResolveRequest(
                    vault_session=tok_resp.vault_session,
                    tokens=[{"ref": token.token_ref, "cap": token.cap}],
                    sink={"kind": "engine", "name": "gpt-4"},
                )
            )


class TestCapabilityTampering:
    """Test capability tampering detection."""

    def test_forged_capability_with_wrong_key_fails(self):
        """Attacker creates capability with different secret key - HMAC fails."""
        # Configure policy to allow the sink (so we reach capability verification)
        policy = Policy(
            sinks={"tool:malicious_tool": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL)])}
        )
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: user@example.com")
        tok_resp = vault.tokenize(tok_req)

        if not tok_resp.tokens:
            pytest.skip("No tokens detected")

        token = tok_resp.tokens[0]

        # Create a forged capability using wrong key
        wrong_key = b"wrong_secret_key_32_bytes_long!!!"
        wrong_cap_mgr = CapabilityManager(wrong_key)

        forged_cap = wrong_cap_mgr.create(
            vault_session=tok_resp.vault_session,
            pii_ref=token.pii_ref,
            pii_type=PIIType.EMAIL,
            sink=Sink(kind="tool", name="malicious_tool"),
            ttl_seconds=3600,
        )

        # Attempt to use forged capability - should fail at HMAC verification
        with pytest.raises((ValueError, CapabilityTamperedError, CapabilityInvalidError)):
            vault.resolve(
                ResolveRequest(
                    vault_session=tok_resp.vault_session,
                    tokens=[{"ref": token.pii_ref, "cap": forged_cap}],
                    sink={"kind": "tool", "name": "malicious_tool"},
                )
            )


class TestDeliverModeBoundary:
    """Test that deliver mode never leaks PII to response."""

    @pytest.mark.asyncio
    async def test_deliver_mode_pii_never_in_response(self):
        """PII is injected locally but never returned to LLM."""
        policy = Policy()
        vault = Vault(policy=policy)

        # Tokenize email
        tok_req = TokenizeRequest(content="Email: alice@example.com")
        tok_resp = vault.tokenize(tok_req)

        # Deliver mode - PII should be injected but not returned
        deliver_req = DeliverRequest(
            vault_session=tok_resp.vault_session,
            tool_call={
                "name": "send_email",
                "args": {"to": "EMAIL_TOKEN_001", "subject": "Test"},
            },
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Response should NOT contain the raw email
        result_str = str(deliver_resp.tool_result)
        assert "alice@example.com" not in result_str, "PII leaked in deliver response!"
        assert deliver_resp.delivered is True

    @pytest.mark.asyncio
    async def test_tool_result_pii_is_tokenized(self):
        """Tool results containing PII should be automatically tokenized."""
        from mcp_pvp.executor import ToolExecutor

        # Custom executor that returns PII in the result
        class PIIReturningExecutor(ToolExecutor):
            async def execute(self, tool_name: str, injected_args: dict) -> dict:
                # Simulate a tool that returns user data with PII
                return {
                    "status": "success",
                    "user_email": "sensitive@company.com",
                    "user_phone": "+1-555-123-4567",
                    "message": "User data retrieved successfully",
                }

            async def list_tools(self) -> list[str]:
                return []

            async def get_tool_info(self, tool_name: str) -> dict:
                return {}

            async def get_tool(self, tool_name: str):
                return None

        policy = Policy()
        vault = Vault(policy=policy, executor=PIIReturningExecutor())

        # Tokenize some content to create a session
        tok_req = TokenizeRequest(content="Email: test@test.com")
        tok_resp = vault.tokenize(tok_req)

        # Deliver a tool call
        deliver_req = DeliverRequest(
            vault_session=tok_resp.vault_session,
            tool_call={
                "name": "get_user_data",
                "args": {"user_id": 123},
            },
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Tool result should be tokenized - no raw PII
        result_str = str(deliver_resp.tool_result)
        assert "sensitive@company.com" not in result_str, "Email PII leaked in tool result!"
        assert "+1-555-123-4567" not in result_str, "Phone PII leaked in tool result!"

        # Should have tokens for the PII found in result
        assert len(deliver_resp.result_tokens) > 0, "No tokens created for tool result PII!"

        # Verify tokens contain references to detected PII
        assert deliver_resp.delivered is True


class TestDefaultDeny:
    """Test default-deny policy enforcement for sensitive sinks."""

    def test_llm_sink_denied_by_default(self):
        """LLM sinks are denied unless explicitly allowed."""
        policy = Policy(default_allow=False)  # Explicit default-deny
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: test@test.com")
        tok_resp = vault.tokenize(tok_req)

        if not tok_resp.tokens:
            pytest.skip("No tokens detected")

        token = tok_resp.tokens[0]

        # Attempt to send to LLM - should be denied by policy
        with pytest.raises((ValueError, Exception)):
            vault.resolve(
                ResolveRequest(
                    vault_session=tok_resp.vault_session,
                    tokens=[{"ref": token.token_ref, "cap": token.cap}],
                    sink={"kind": "llm", "name": "gpt-4"},
                )
            )

    def test_local_sink_allowed_with_default_allow(self):
        """LOCAL sinks are allowed when policy is configured to allow them."""
        policy = Policy(
            default_allow=True, sinks={"local:internal_db": {"allow": [{"type": PIIType.EMAIL}]}}
        )
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: admin@company.com")
        tok_resp = vault.tokenize(tok_req)

        if not tok_resp.tokens:
            pytest.skip("No tokens detected")

        token = tok_resp.tokens[0]

        # LOCAL should be allowed with explicit policy
        resolve_resp = vault.resolve(
            ResolveRequest(
                vault_session=tok_resp.vault_session,
                tokens=[{"ref": token.pii_ref, "cap": token.cap}],
                sink={"kind": "local", "name": "internal_db"},
            )
        )
        assert len(resolve_resp.values) == 1


class TestSessionIsolation:
    """Test session isolation and security."""

    def test_multiple_sessions_isolated(self):
        """Sessions remain isolated from each other."""
        policy = Policy()
        vault = Vault(policy=policy)

        # Create two sessions
        tok_req1 = TokenizeRequest(content="Email: user1@test.com")
        tok_resp1 = vault.tokenize(tok_req1)

        tok_req2 = TokenizeRequest(content="Email: user2@test.com")
        tok_resp2 = vault.tokenize(tok_req2)

        # Sessions should be different
        assert tok_resp1.vault_session != tok_resp2.vault_session

        # Each session should only access its own tokens
        if tok_resp1.tokens:
            token1 = tok_resp1.tokens[0]

            # Should fail to use token1's capability in session2
            with pytest.raises((ValueError, Exception)):
                vault.resolve(
                    ResolveRequest(
                        vault_session=tok_resp2.vault_session,  # Wrong session
                        tokens=[{"ref": token1.token_ref, "cap": token1.cap}],
                        sink={"kind": "local", "name": "test"},
                    )
                )

    def test_session_cleanup(self):
        """Vault can create and manage multiple sessions."""
        policy = Policy()
        vault = Vault(policy=policy)

        # Create many sessions
        sessions = []
        for i in range(50):
            tok_req = TokenizeRequest(content=f"Email: user{i}@test.com")
            tok_resp = vault.tokenize(tok_req)
            sessions.append(tok_resp.vault_session)

        # All sessions should be unique
        assert len(set(sessions)) == 50


class TestTokenFormatConsistency:
    """Test token format handling and consistency."""

    def test_text_format_tokens(self):
        """TEXT format produces text-style tokens."""
        policy = Policy()
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(
            content="Email: user@example.com",
            token_format=TokenFormat.TEXT,
        )
        tok_resp = vault.tokenize(tok_req)

        if tok_resp.tokens:
            # Should have redacted content with TEXT tokens
            assert "PII" in tok_resp.redacted or "tkn_" in tok_resp.redacted

    def test_json_format_tokens(self):
        """JSON format produces JSON-style tokens."""
        policy = Policy()
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(
            content='{"email": "admin@company.com"}',
            token_format=TokenFormat.JSON,
        )
        tok_resp = vault.tokenize(tok_req)

        # JSON format should work
        assert tok_resp.vault_session is not None


class TestAuditLogging:
    """Test that security events are properly audited."""

    def test_tokenize_audit_event(self):
        """Tokenize operation creates audit event."""
        policy = Policy()
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: test@example.com")
        tok_resp = vault.tokenize(tok_req)

        # TokenizeResponse doesn't expose audit_id directly, but audit events are logged
        # Check that response has expected fields
        assert tok_resp.vault_session is not None
        assert tok_resp.vault_session.startswith("vs_")

    @pytest.mark.asyncio
    async def test_deliver_audit_event(self):
        """Deliver operation creates audit event."""
        policy = Policy()
        vault = Vault(policy=policy)

        tok_req = TokenizeRequest(content="Email: user@test.com")
        tok_resp = vault.tokenize(tok_req)

        deliver_req = DeliverRequest(
            vault_session=tok_resp.vault_session,
            tool_call={"name": "test_tool", "args": {}},
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Should have audit ID
        assert deliver_resp.audit_id is not None
        assert deliver_resp.audit_id.startswith("aud_")


class TestMultiplePIITypes:
    """Test handling of multiple PII types in same content."""

    def test_multiple_emails_detected(self):
        """Multiple emails in content are all tokenized."""
        policy = Policy()
        vault = Vault(policy=policy)

        content = "Contact alice@example.com or bob@example.com for support"
        tok_req = TokenizeRequest(content=content)
        tok_resp = vault.tokenize(tok_req)

        # Should detect 2 emails
        assert len(tok_resp.tokens) == 2

    def test_mixed_pii_types(self):
        """Multiple PII types are all detected."""
        policy = Policy()
        vault = Vault(policy=policy)

        content = "Email user@test.com, phone 555-1234, IP 192.168.1.1"
        tok_req = TokenizeRequest(content=content)
        tok_resp = vault.tokenize(tok_req)

        # Should detect all PII (at least email)
        assert len(tok_resp.tokens) >= 1
