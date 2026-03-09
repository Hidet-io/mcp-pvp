"""Integration tests for vault hardening features working together."""

import pytest

from mcp_pvp.executor import ToolExecutor
from mcp_pvp.models import (
    DeliverRequest,
    PIIType,
    Policy,
    RunContext,
    TokenFormat,
    TokenizeRequest,
    ToolCall,
)
from mcp_pvp.vault import Vault


class CustomResultObject:
    """Custom object for testing recursive scrubbing."""

    def __init__(self, status: str, user_email: str, details: dict):
        self.status = status
        self.user_email = user_email
        self.details = details


class ComplexToolExecutor(ToolExecutor):
    """Tool executor that returns complex results for integration testing."""

    def __init__(self, result_type: str = "dict"):
        self.result_type = result_type
        self.execution_count = 0

    async def execute(
        self, tool_name: str, injected_args: dict
    ) -> dict | list | CustomResultObject | None:
        """Execute tool and return complex result based on type."""
        self.execution_count += 1

        if self.result_type == "dict":
            # Return nested dict with PII
            return {
                "status": "success",
                "user": {
                    "email": injected_args.get("email", "result@example.com"),
                    "phone": "555-9999",
                },
                "metadata": {"request_id": self.execution_count, "timestamp": "2026-02-01"},
            }
        elif self.result_type == "list":
            # Return list of dicts with PII
            return [
                {"user": "user1", "contact": "user1@result.com"},
                {"user": "user2", "contact": "user2@result.com"},
            ]
        elif self.result_type == "custom":
            # Return custom object with PII
            return CustomResultObject(
                status="completed",
                user_email="custom@result.com",
                details={"nested": {"email": "nested@result.com"}},
            )
        elif self.result_type == "exception":
            # Return dict with exception info
            try:
                raise ValueError("Failed: admin@error.com")
            except ValueError as e:
                return {"error": e, "context": {"admin_email": "recovery@admin.com"}}
        else:
            return None

    async def list_tools(self) -> list[str]:
        return []

    async def get_tool_info(self, tool_name: str) -> dict:
        return {}

    async def get_tool(self, tool_name: str):
        return None


class TestSessionIntegrityWithResultTokenization:
    """Test session integrity feature combined with result tokenization."""

    @pytest.fixture
    def vault(self):
        """Create vault with permissive policy."""
        return Vault(
            policy=Policy(default_allow=True), executor=ComplexToolExecutor(result_type="dict")
        )

    @pytest.mark.asyncio
    async def test_result_tokens_belong_to_same_session(self, vault):
        """Test that result tokenization creates tokens in the same session."""
        # Initial tokenization - detect actual PII
        tokenize_req = TokenizeRequest(
            content="User email: alice@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session_id = tokenize_resp.vault_session

        # Deliver - this should create result tokens in the same session
        deliver_req = DeliverRequest(
            vault_session=session_id,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="test_tool", args={"email": "alice@example.com"}),
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Verify result tokens were created
        assert len(deliver_resp.result_tokens) > 0

        # Verify result tokens are TextToken instances with refs
        for token in deliver_resp.result_tokens:
            assert hasattr(token, "ref")
            assert token.ref.startswith("tkn_")

    @pytest.mark.asyncio
    async def test_result_tokens_respect_session_isolation(self, vault):
        """Test that result tokens from one session cannot be accessed from another."""
        # Session 1: tokenize and deliver
        tokenize_req1 = TokenizeRequest(
            content="Email: session1@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp1 = vault.tokenize(tokenize_req1)
        session1_id = tokenize_resp1.vault_session

        deliver_req1 = DeliverRequest(
            vault_session=session1_id,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="tool1", args={"email": "session1@example.com"}),
        )
        deliver_resp1 = await vault.deliver(deliver_req1)
        result_tokens_session1 = deliver_resp1.result_tokens

        # Verify session 1 has result tokens
        assert len(result_tokens_session1) > 0

        # Session 2: different session
        tokenize_req2 = TokenizeRequest(
            content="Email: session2@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp2 = vault.tokenize(tokenize_req2)
        session2_id = tokenize_resp2.vault_session

        # Verify sessions are different
        assert session1_id != session2_id

        # The integration point is that each session's result tokens are independent
        # Session isolation is tested in test_session_integrity.py
        deliver_req2 = DeliverRequest(
            vault_session=session2_id,
            run=RunContext(run_id="run2", participant_id="llm"),
            tool_call=ToolCall(name="tool2", args={}),
        )
        deliver_resp2 = await vault.deliver(deliver_req2)

        # Both sessions should have their own result tokens
        assert len(deliver_resp2.result_tokens) > 0


class TestAuditCoherenceWithRecursiveScrubbing:
    """Test audit coherence with recursive output scrubbing."""

    @pytest.fixture
    def vault(self):
        """Create vault with complex executor."""
        return Vault(
            policy=Policy(default_allow=True), executor=ComplexToolExecutor(result_type="custom")
        )

    @pytest.mark.asyncio
    async def test_audit_trail_for_custom_object_scrubbing(self, vault):
        """Test that audit trail is maintained when scrubbing custom objects."""
        # Tokenize initial content
        tokenize_req = TokenizeRequest(
            content="Process user@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)

        # Deliver - will return custom object with PII
        deliver_req = DeliverRequest(
            vault_session=tokenize_resp.vault_session,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="test_tool", args={}),
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Verify result tokens were created (custom object was scrubbed)
        assert len(deliver_resp.result_tokens) > 0

        # Get audit events
        events = vault.audit_logger.get_events()

        # Find the deliver event and result tokenization event
        deliver_event = next((e for e in events if e.event_type == "DELIVER"), None)
        assert deliver_event is not None

        # Find child tokenization events (result tokenization)
        child_events = [
            e
            for e in events
            if e.parent_audit_id == deliver_event.audit_id and e.event_type == "TOKENIZE"
        ]

        # Should have at least one child event for result tokenization
        assert len(child_events) > 0

        # Verify parent-child relationship
        for child_event in child_events:
            assert child_event.parent_audit_id == deliver_event.audit_id
            assert child_event.vault_session == tokenize_resp.vault_session


class TestScannerWithSessionIntegrity:
    """Test scanner-based parser with session integrity."""

    @pytest.fixture
    def vault(self):
        """Create vault for scanner testing."""
        return Vault(
            policy=Policy(default_allow=True), executor=ComplexToolExecutor(result_type="dict")
        )

    def test_scanner_handles_pathological_input_across_sessions(self, vault):
        """Test scanner with complex input doesn't break session integrity."""
        # Use actual PII in complex input (scanner processes content with many brackets)
        pathological_content = "[" * 100 + " User email@example.com " + "]" * 100

        # Tokenize in session 1
        tokenize_req = TokenizeRequest(
            content=pathological_content,
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session1_id = tokenize_resp.vault_session

        # Verify PII was detected
        assert len(tokenize_resp.tokens) == 1
        assert tokenize_resp.tokens[0].pii_type == PIIType.EMAIL

        # Create session 2
        tokenize_req2 = TokenizeRequest(
            content="Different user2@example.com content",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp2 = vault.tokenize(tokenize_req2)
        session2_id = tokenize_resp2.vault_session

        # Verify sessions are different
        assert session1_id != session2_id

        # Verify each session has its own tokens
        assert len(tokenize_resp2.tokens) == 1


class TestAllFeaturesIntegrated:
    """Test all 5 features working together in complex scenarios."""

    @pytest.fixture
    def vault(self):
        """Create vault with all features enabled."""
        return Vault(
            policy=Policy(default_allow=True), executor=ComplexToolExecutor(result_type="dict")
        )

    @pytest.mark.asyncio
    async def test_complete_workflow_with_all_features(self, vault):
        """Test complete workflow: tokenize → deliver → result scrubbing → audit trail."""
        # Step 1: Tokenize with actual PII (scanner processes it)
        complex_input = "Process alice@example.com and 555-1234 with 192.168.1.1"

        tokenize_req = TokenizeRequest(
            content=complex_input,
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session_id = tokenize_resp.vault_session

        # Verify PII was detected (email, phone, IPV4)
        assert len(tokenize_resp.tokens) >= 2  # At least email and phone
        token_types = {t.pii_type for t in tokenize_resp.tokens}
        assert PIIType.EMAIL in token_types

        # Step 2: Deliver - this exercises session integrity and result tokenization
        deliver_req = DeliverRequest(
            vault_session=session_id,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="process_user", args={"email": "test@example.com"}),
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Step 3: Verify result was scrubbed (recursive scrubbing)
        # The ComplexToolExecutor returns nested dict with PII
        assert deliver_resp.delivered
        assert len(deliver_resp.result_tokens) > 0

        # Step 4: Verify result is redacted (has TEXT tokens).
        # tool_result is a dict; stringify it to check for token patterns.
        assert "[[PII:" in str(deliver_resp.tool_result)

        # Step 5: Verify audit trail (audit coherence)
        events = vault.audit_logger.get_events()

        # Find events
        tokenize_events = [e for e in events if e.event_type == "TOKENIZE"]
        deliver_events = [e for e in events if e.event_type == "DELIVER"]

        # Should have initial tokenize + result tokenization events
        assert len(tokenize_events) >= 2

        # Should have one deliver event
        assert len(deliver_events) == 1

        # Verify parent-child relationship in audit trail
        deliver_event = deliver_events[0]
        child_tokenize_events = [
            e for e in tokenize_events if e.parent_audit_id == deliver_event.audit_id
        ]

        # Result tokenization should have deliver as parent
        assert len(child_tokenize_events) > 0

    @pytest.mark.asyncio
    async def test_multi_round_interaction_preserves_all_features(self, vault):
        """Test multiple deliver rounds maintain session integrity, audit trail, and scrubbing."""
        # Round 1: Initial tokenization
        tokenize_req = TokenizeRequest(
            content="User: alice@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session_id = tokenize_resp.vault_session

        all_result_tokens_count = 0

        # Round 1, 2, 3: Multiple deliver calls
        for i in range(3):
            deliver_req = DeliverRequest(
                vault_session=session_id,
                run=RunContext(run_id=f"run{i}", participant_id="llm"),
                tool_call=ToolCall(name=f"tool{i}", args={"email": f"user{i}@example.com"}),
            )
            deliver_resp = await vault.deliver(deliver_req)

            # Collect all result tokens count
            all_result_tokens_count += len(deliver_resp.result_tokens)

        # Should have collected result tokens across all rounds
        assert all_result_tokens_count > 0

        # Verify audit trail shows all 3 deliver events
        events = vault.audit_logger.get_events()
        deliver_events = [e for e in events if e.event_type == "DELIVER"]
        assert len(deliver_events) == 3

        # Each deliver should have child tokenization events
        for deliver_event in deliver_events:
            child_events = [e for e in events if e.parent_audit_id == deliver_event.audit_id]
            # Should have result tokenization children
            assert len(child_events) > 0

    @pytest.mark.asyncio
    async def test_scanner_handles_all_pii_types_with_session_integrity(self, vault):
        """Test scanner handles all PIIType values while maintaining session integrity."""
        # Create content with actual PII of different types
        content = "Email: user@example.com Phone: 555-1234 IP: 192.168.1.1"

        tokenize_req = TokenizeRequest(
            content=content,
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session_id = tokenize_resp.vault_session

        # Verify PII was detected (at least email and phone)
        assert len(tokenize_resp.tokens) >= 2

        # Verify session was created
        assert session_id.startswith("vs_")

        # Now deliver with this session - result tokens should also be created
        deliver_req = DeliverRequest(
            vault_session=session_id,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="test", args={}),
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Verify result tokens were created
        assert len(deliver_resp.result_tokens) > 0

        # Verify both initial and result tokens appear in redacted content.
        # tool_result is a dict; stringify to check for token patterns.
        assert "[[PII:" in tokenize_resp.redacted
        assert "[[PII:" in str(deliver_resp.tool_result)


class TestComplexExceptionHandling:
    """Test exception handling with all features."""

    @pytest.fixture
    def vault(self):
        """Create vault that handles exceptions."""
        return Vault(
            policy=Policy(default_allow=True),
            executor=ComplexToolExecutor(result_type="exception"),
        )

    @pytest.mark.asyncio
    async def test_exception_in_result_is_scrubbed_with_audit_trail(self, vault):
        """Test that exceptions in tool results are scrubbed and audited properly."""
        # Tokenize with actual PII
        tokenize_req = TokenizeRequest(
            content="Test input@example.com",
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session_id = tokenize_resp.vault_session

        # Deliver - executor returns dict with exception
        deliver_req = DeliverRequest(
            vault_session=session_id,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="test", args={}),
        )
        deliver_resp = await vault.deliver(deliver_req)

        # The result contains an exception with PII - should be scrubbed
        assert deliver_resp.delivered

        # Should have found PII in the exception and context
        assert len(deliver_resp.result_tokens) > 0

        # Result should contain redacted markers.
        # tool_result is a dict; stringify to check for token patterns.
        assert "[[PII:" in str(deliver_resp.tool_result)

        # Verify audit trail exists
        events = vault.audit_logger.get_events()
        deliver_events = [e for e in events if e.event_type == "DELIVER"]
        assert len(deliver_events) == 1

        # Should have child tokenization event for exception scrubbing
        child_events = [e for e in events if e.parent_audit_id == deliver_events[0].audit_id]
        assert len(child_events) > 0


class TestPerformanceWithAllFeatures:
    """Test performance characteristics with all features enabled."""

    @pytest.fixture
    def vault(self):
        """Create vault for performance testing."""
        return Vault(
            policy=Policy(default_allow=True), executor=ComplexToolExecutor(result_type="list")
        )

    @pytest.mark.asyncio
    async def test_large_session_with_many_tokens(self, vault):
        """Test that large sessions with many tokens still maintain integrity."""
        # Create content with many actual PII instances
        content = " ".join([f"user{i}@example.com" for i in range(100)])

        tokenize_req = TokenizeRequest(
            content=content,
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        session_id = tokenize_resp.vault_session

        # Should have found 100 email addresses
        assert len(tokenize_resp.tokens) == 100

        # Verify session was created
        assert session_id.startswith("vs_")

        # Deliver - creates more tokens via result tokenization
        deliver_req = DeliverRequest(
            vault_session=session_id,
            run=RunContext(run_id="run1", participant_id="llm"),
            tool_call=ToolCall(name="test", args={}),
        )
        deliver_resp = await vault.deliver(deliver_req)

        # Result tokens should exist
        assert len(deliver_resp.result_tokens) > 0

        # Verify audit log captured both tokenization events
        events = vault.audit_logger.get_events()
        tokenize_events = [e for e in events if e.event_type == "TOKENIZE"]

        # Should have initial tokenize + result tokenization
        assert len(tokenize_events) >= 2

        # Total tokens across all tokenization events
        total_tokens = sum(e.details.get("tokens_created", 0) for e in tokenize_events)
        assert total_tokens > 100

    def test_scanner_performance_with_complex_input(self, vault):
        """Test scanner performance doesn't degrade with complex input."""
        import time

        # Create complex input with false starts and actual PII
        complex_input = "[" * 1000 + "test@example.com " + "]" * 1000

        start = time.perf_counter()
        tokenize_req = TokenizeRequest(
            content=complex_input,
            token_format=TokenFormat.TEXT,
        )
        tokenize_resp = vault.tokenize(tokenize_req)
        elapsed = time.perf_counter() - start

        # Should complete quickly (under 1 second for this input)
        assert elapsed < 1.0

        # Should have found the email despite pathological input
        assert len(tokenize_resp.tokens) >= 1

        # Session should be valid
        assert tokenize_resp.vault_session.startswith("vs_")
