"""Tests for ToolExecutor integration."""

import json

import pytest

from mcp_pvp import (
    DeliverRequest,
    DummyExecutor,
    PIIType,
    Policy,
    PolicyAllow,
    SinkPolicy,
    TokenFormat,
    TokenizeRequest,
    ToolCall,
    ToolExecutor,
    Vault,
)


class CustomExecutor(ToolExecutor):
    """Test executor that records execution."""

    def __init__(self):
        self.executions = []

    def execute(self, tool_name: str, injected_args: dict) -> dict:
        """Record execution and return result."""
        self.executions.append({"tool": tool_name, "args": injected_args})
        return {"success": True, "tool": tool_name}


def test_dummy_executor_default():
    """Test that DummyExecutor is used by default."""
    vault = Vault()
    assert isinstance(vault.executor, DummyExecutor)


def test_custom_executor_integration():
    """Test vault.deliver() with custom executor."""
    # Create custom executor
    executor = CustomExecutor()

    # Configure policy to allow tool:send_email
    policy = Policy(sinks={"tool:send_email": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL)])})

    vault = Vault(policy=policy, executor=executor)

    # Tokenize email
    tok_req = TokenizeRequest(
        content="Send email to alice@example.com", token_format=TokenFormat.JSON
    )
    tok_resp = vault.tokenize(tok_req)

    assert len(tok_resp.tokens) == 1
    token = tok_resp.tokens[0]

    # Deliver with tool call (token embedded in args)
    deliver_req = DeliverRequest(
        vault_session=tok_resp.vault_session,
        tool_call=ToolCall(
            name="send_email", args={"to": token.model_dump(by_alias=True), "subject": "Hi"}
        ),
    )

    deliver_resp = vault.deliver(deliver_req)

    # Verify executor was called
    assert len(executor.executions) == 1
    execution = executor.executions[0]
    assert execution["tool"] == "send_email"
    assert "to" in execution["args"]
    # Raw PII was injected
    assert execution["args"]["to"] == "alice@example.com"
    tool_result = json.loads(deliver_resp.tool_result)

    # Verify response
    assert deliver_resp.delivered is True
    assert tool_result["success"] is True


def test_dummy_executor_stub_response():
    """Test DummyExecutor returns stub response."""
    executor = DummyExecutor()

    result = executor.execute("test_tool", {"arg1": "value1", "arg2": "value2"})

    assert result["status"] == "stub"
    assert result["tool"] == "test_tool"
    assert result["message"] == "DummyExecutor does not execute real tools"
    assert result["args_received"] is True
    assert result["arg_count"] == 2


def test_executor_failure_propagates():
    """Test that executor exceptions propagate to caller."""

    class FailingExecutor(ToolExecutor):
        def execute(self, tool_name: str, injected_args: dict) -> dict:
            raise ValueError("Tool execution failed")

    policy = Policy(
        sinks={"tool:failing_tool": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL)])}
    )

    vault = Vault(policy=policy, executor=FailingExecutor())

    # Tokenize
    tok_req = TokenizeRequest(content="Email: test@example.com")
    tok_resp = vault.tokenize(tok_req)
    token = tok_resp.tokens[0]

    # Deliver should propagate exception
    deliver_req = DeliverRequest(
        vault_session=tok_resp.vault_session,
        tool_call=ToolCall(name="failing_tool", args={"email": token.model_dump(by_alias=True)}),
    )

    with pytest.raises(ValueError, match="Tool execution failed"):
        vault.deliver(deliver_req)


def test_executor_receives_pii_injected_args():
    """Test that executor receives arguments with PII injected."""

    class InspectingExecutor(ToolExecutor):
        def __init__(self):
            self.last_args = None

        def execute(self, tool_name: str, injected_args: dict) -> dict:
            self.last_args = injected_args
            return {"done": True}

    executor = InspectingExecutor()
    policy = Policy(sinks={"tool:test": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL)])})
    vault = Vault(policy=policy, executor=executor)

    # Tokenize multiple emails
    tok_req = TokenizeRequest(
        content="Emails: alice@example.com, bob@example.com", token_format=TokenFormat.JSON
    )
    tok_resp = vault.tokenize(tok_req)

    assert len(tok_resp.tokens) == 2

    # Deliver with both tokens
    deliver_req = DeliverRequest(
        vault_session=tok_resp.vault_session,
        tool_call=ToolCall(
            name="test",
            args={
                "recipient1": tok_resp.tokens[0].model_dump(by_alias=True),
                "recipient2": tok_resp.tokens[1].model_dump(by_alias=True),
            },
        ),
    )

    vault.deliver(deliver_req)

    # Verify raw PII was injected
    assert executor.last_args is not None
    assert executor.last_args["recipient1"] == "alice@example.com"
    assert executor.last_args["recipient2"] == "bob@example.com"
