"""Integration tests for vault operations."""

from typing import Any

import pytest

from mcp_pvp import (
    DeliverRequest,
    PIIType,
    Policy,
    PolicyAllow,
    ResolveRequest,
    ResolveTokenRequest,
    Sink,
    SinkKind,
    SinkPolicy,
    TokenFormat,
    TokenizeRequest,
    ToolCall,
    ToolExecutor,
    Vault,
)


class CustomExecutor(ToolExecutor):
    """Test executor that records the args it receives."""

    def __init__(self):
        self.last_args = None

    async def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
        """Record args and return a simple response without PII."""
        self.last_args = injected_args
        return f"Tool {tool_name} executed successfully"

    async def get_tool_info(self, tool_name: str) -> dict[str, Any]:
        """Return stub tool info."""
        tool_info = {
            "send_email": {
                "description": "Send an email to a recipient",
                "args": {"recipient_email": "string", "subject": "string", "body": "string"},
            }
        }
        return tool_info.get(tool_name, {})

    async def list_tools(self) -> list[str]:
        """Return list of available tool names."""
        return ["send_email"]

    async def get_tool(self, tool_name: str) -> Any:
        """Return stub tool callable."""
        tool_names = await self.list_tools()
        if tool_name not in tool_names:
            raise KeyError(f"Tool '{tool_name}' not found in CustomExecutor")

        # Return a simple stub callable
        async def stub_tool(**kwargs):
            return {
                "status": "stub",
                "message": f"CustomExecutor stub for tool '{tool_name}'",
                "args": kwargs,
            }

        return stub_tool


def test_vault_tokenize_text_format() -> None:
    """Test vault tokenization with text format."""
    vault = Vault()

    request = TokenizeRequest(
        content="Email me at test@example.com",
        token_format=TokenFormat.TEXT,
        include_caps=False,
    )

    response = vault.tokenize(request)

    assert response.vault_session.startswith("vs_")
    assert "[[PII:EMAIL:" in response.redacted
    assert response.stats.detections == 1
    assert response.stats.tokens_created == 1
    assert PIIType.EMAIL in response.stats.types


def test_vault_tokenize_json_format() -> None:
    """Test vault tokenization with JSON format."""
    vault = Vault()

    request = TokenizeRequest(
        content="Call 555-1234",
        token_format=TokenFormat.JSON,
        include_caps=True,
    )

    response = vault.tokenize(request)

    assert response.vault_session.startswith("vs_")
    assert len(response.tokens) == 1
    token = response.tokens[0]
    assert hasattr(token, "pii_ref")
    assert hasattr(token, "cap")


def test_vault_resolve_with_policy() -> None:
    """Test vault resolve with policy enforcement."""
    policy = Policy(
        sinks={
            "tool:test_tool": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=None)])
        }
    )
    vault = Vault(policy=policy)

    # Tokenize
    tokenize_req = TokenizeRequest(
        content="test@example.com",
        token_format=TokenFormat.JSON,
        include_caps=True,
    )
    tokenize_resp = vault.tokenize(tokenize_req)

    token = tokenize_resp.tokens[0]

    # Resolve
    resolve_req = ResolveRequest(
        vault_session=tokenize_resp.vault_session,
        tokens=[ResolveTokenRequest(ref=token.pii_ref, cap=token.cap)],  # type: ignore
        sink=Sink(kind=SinkKind.TOOL, name="test_tool", arg_path="email"),
    )

    resolve_resp = vault.resolve(resolve_req)

    assert token.pii_ref in resolve_resp.values  # type: ignore
    assert resolve_resp.values[token.pii_ref] == "test@example.com"  # type: ignore
    assert resolve_resp.audit_id.startswith("aud_")


@pytest.mark.asyncio
async def test_vault_deliver_mode() -> None:
    """Test vault deliver mode."""
    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["to"])])
        }
    )
    vault = Vault(policy=policy, executor=CustomExecutor())

    # Tokenize
    tokenize_req = TokenizeRequest(
        content="alice@example.com",
        token_format=TokenFormat.JSON,
        include_caps=True,
    )
    tokenize_resp = vault.tokenize(tokenize_req)

    token = tokenize_resp.tokens[0]

    # Deliver
    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="send_email",
            args={"to": token.model_dump(by_alias=True), "subject": "Test"},
        ),
    )

    deliver_resp = await vault.deliver(deliver_req)

    assert deliver_resp.delivered is True
    assert deliver_resp.audit_id.startswith("aud_")
    assert deliver_resp.tool_result is not None


def test_vault_multiple_detections() -> None:
    """Test vault with multiple PII detections."""
    vault = Vault()

    request = TokenizeRequest(
        content="Email alice@example.com or call 555-1234",
        token_format=TokenFormat.JSON,
    )

    response = vault.tokenize(request)

    assert response.stats.detections == 2
    assert response.stats.tokens_created == 2
    assert len(response.tokens) == 2
    assert PIIType.EMAIL in response.stats.types
    assert PIIType.PHONE in response.stats.types


@pytest.mark.asyncio
async def test_vault_deliver_with_text_tokens_in_strings() -> None:
    """Test vault deliver mode with TEXT format tokens embedded in string arguments."""
    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(
                allow=[
                    PolicyAllow(type=PIIType.EMAIL, arg_paths=["body"]),
                    PolicyAllow(type=PIIType.PHONE, arg_paths=["body"]),
                ]
            )
        }
    )
    executor = CustomExecutor()
    vault = Vault(policy=policy, executor=executor)

    # Tokenize
    tokenize_req = TokenizeRequest(
        content="Email alice@example.com or call 555-1234",
        token_format=TokenFormat.JSON,
    )
    tokenize_resp = vault.tokenize(tokenize_req)

    assert len(tokenize_resp.tokens) == 2
    email_token = tokenize_resp.tokens[0]
    phone_token = tokenize_resp.tokens[1]

    # Create tool call with TEXT tokens embedded in body string
    body_with_tokens = f"Please contact [[PII:EMAIL:{email_token.pii_ref}]] or call [[PII:PHONE:{phone_token.pii_ref}]]"

    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="send_email",
            args={
                "to": "admin@example.com",
                "body": body_with_tokens,
                "subject": "Contact Info",
            },
        ),
    )

    deliver_resp = await vault.deliver(deliver_req)

    assert deliver_resp.delivered is True
    # Verify executor received PII-injected args (TEXT tokens were replaced)
    assert executor.last_args is not None
    assert "alice@example.com" in executor.last_args["body"]
    assert "555-1234" in executor.last_args["body"]
    assert "[[PII:" not in executor.last_args["body"]  # No tokens should remain


@pytest.mark.asyncio
async def test_vault_deliver_with_mixed_json_and_text_tokens() -> None:
    """Test vault deliver mode with both JSON and TEXT format tokens."""
    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(
                allow=[
                    PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "body"]),
                    PolicyAllow(type=PIIType.PHONE, arg_paths=["body"]),
                ]
            )
        }
    )
    executor = CustomExecutor()
    vault = Vault(policy=policy, executor=executor)

    # Tokenize
    tokenize_req = TokenizeRequest(
        content="Email alice@example.com or call 555-1234",
        token_format=TokenFormat.JSON,
    )
    tokenize_resp = vault.tokenize(tokenize_req)

    email_token = tokenize_resp.tokens[0]
    phone_token = tokenize_resp.tokens[1]

    # Create tool call with:
    # - JSON token in 'to' field (structured)
    # - TEXT tokens in 'body' field (mixed content)
    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="send_email",
            args={
                "to": email_token.model_dump(by_alias=True),  # JSON format
                "body": f"Reply to [[PII:EMAIL:{email_token.pii_ref}]] or call [[PII:PHONE:{phone_token.pii_ref}]]",  # TEXT format
                "subject": "Mixed Tokens",
            },
        ),
    )

    deliver_resp = await vault.deliver(deliver_req)

    assert deliver_resp.delivered is True
    # Verify executor received both JSON and TEXT tokens replaced
    assert executor.last_args is not None
    assert executor.last_args["to"] == "alice@example.com"  # JSON token replaced
    assert "alice@example.com" in executor.last_args["body"]  # TEXT token replaced
    assert "555-1234" in executor.last_args["body"]  # TEXT token replaced
    assert "[[PII:" not in executor.last_args["body"]  # No TEXT tokens remain
    assert "$pii_ref" not in str(executor.last_args)  # No JSON tokens remain


@pytest.mark.asyncio
async def test_vault_deliver_text_tokens_policy_denial() -> None:
    """Test that TEXT tokens in strings are subject to policy enforcement."""
    # Policy only allows EMAIL in 'to', not in 'body'
    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["to"])])
        }
    )
    vault = Vault(policy=policy)

    # Tokenize
    tokenize_req = TokenizeRequest(
        content="alice@example.com",
        token_format=TokenFormat.JSON,
    )
    tokenize_resp = vault.tokenize(tokenize_req)
    email_token = tokenize_resp.tokens[0]

    # Try to use TEXT token in 'body' (should be denied)
    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="send_email",
            args={
                "to": "admin@example.com",
                "body": f"Contact [[PII:EMAIL:{email_token.pii_ref}]]",
                "subject": "Test",
            },
        ),
    )

    # Should raise PolicyDeniedError
    from mcp_pvp.errors import PolicyDeniedError

    with pytest.raises(PolicyDeniedError):
        await vault.deliver(deliver_req)


@pytest.mark.asyncio
async def test_vault_deliver_text_tokens_nested_objects() -> None:
    """Test TEXT tokens in nested object structures."""
    policy = Policy(
        sinks={
            "tool:complex_tool": SinkPolicy(
                allow=[
                    PolicyAllow(type=PIIType.EMAIL, arg_paths=["config"]),
                    PolicyAllow(type=PIIType.PHONE, arg_paths=["config"]),
                ]
            )
        }
    )
    executor = CustomExecutor()
    vault = Vault(policy=policy, executor=executor)

    # Tokenize
    tokenize_req = TokenizeRequest(
        content="Email alice@example.com or call 555-1234",
        token_format=TokenFormat.JSON,
    )
    tokenize_resp = vault.tokenize(tokenize_req)

    email_token = tokenize_resp.tokens[0]
    phone_token = tokenize_resp.tokens[1]

    # Create tool call with TEXT tokens in nested structure
    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="complex_tool",
            args={
                "config": {
                    "contact_info": f"Email: [[PII:EMAIL:{email_token.pii_ref}]], Phone: [[PII:PHONE:{phone_token.pii_ref}]]",
                    "nested": {"deep": f"Alternate: [[PII:EMAIL:{email_token.pii_ref}]]"},
                }
            },
        ),
    )

    deliver_resp = await vault.deliver(deliver_req)

    assert deliver_resp.delivered is True
    # Verify executor received all TEXT tokens replaced in nested structure
    assert executor.last_args is not None
    config_info = executor.last_args["config"]["contact_info"]
    assert "alice@example.com" in config_info
    assert "555-1234" in config_info
    deep_info = executor.last_args["config"]["nested"]["deep"]
    assert "alice@example.com" in deep_info
    assert "[[PII:" not in str(executor.last_args)  # No tokens should remain


@pytest.mark.asyncio
async def test_vault_deliver_text_tokens_in_lists() -> None:
    """Test TEXT tokens in list structures."""
    policy = Policy(
        sinks={
            "tool:batch_process": SinkPolicy(
                allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["messages"])]
            )
        }
    )
    executor = CustomExecutor()
    vault = Vault(policy=policy, executor=executor)

    # Tokenize multiple emails
    tokenize_req = TokenizeRequest(
        content="alice@example.com and bob@example.com",
        token_format=TokenFormat.JSON,
    )
    tokenize_resp = vault.tokenize(tokenize_req)

    assert len(tokenize_resp.tokens) == 2
    token1 = tokenize_resp.tokens[0]
    token2 = tokenize_resp.tokens[1]

    # Create tool call with TEXT tokens in list
    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="batch_process",
            args={
                "messages": [
                    f"Message to [[PII:EMAIL:{token1.pii_ref}]]",
                    f"Message to [[PII:EMAIL:{token2.pii_ref}]]",
                    f"Both: [[PII:EMAIL:{token1.pii_ref}]] and [[PII:EMAIL:{token2.pii_ref}]]",
                ]
            },
        ),
    )

    deliver_resp = await vault.deliver(deliver_req)

    assert deliver_resp.delivered is True
    # Verify executor received all TEXT tokens replaced in list
    assert executor.last_args is not None
    messages = executor.last_args["messages"]
    assert "alice@example.com" in messages[0]
    assert "bob@example.com" in messages[1]
    assert "alice@example.com" in messages[2]
    assert "bob@example.com" in messages[2]
    assert "[[PII:" not in str(messages)  # No tokens should remain


@pytest.mark.asyncio
async def test_vault_deliver_duplicate_text_token_disclosure_counting() -> None:
    """Test that duplicate TEXT token refs only count as one disclosure."""
    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(
                allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["body"])]
            )
        }
    )
    executor = CustomExecutor()
    vault = Vault(policy=policy, executor=executor)

    # Tokenize
    tokenize_req = TokenizeRequest(content="alice@example.com", token_format=TokenFormat.JSON)
    tokenize_resp = vault.tokenize(tokenize_req)
    email_token = tokenize_resp.tokens[0]

    # Create tool call where same TEXT token appears 3 times
    deliver_req = DeliverRequest(
        vault_session=tokenize_resp.vault_session,
        tool_call=ToolCall(
            name="send_email",
            args={
                "to": "admin@example.com",
                "body": f"Contact [[PII:EMAIL:{email_token.pii_ref}]], again [[PII:EMAIL:{email_token.pii_ref}]], and once more [[PII:EMAIL:{email_token.pii_ref}]]",
                "subject": "Test",
            },
        ),
    )

    deliver_resp = await vault.deliver(deliver_req)

    assert deliver_resp.delivered is True

    # Verify the token was replaced in all 3 locations
    assert executor.last_args["body"].count("alice@example.com") == 3
    assert "[[PII:" not in executor.last_args["body"]

    # Verify disclosure was only counted once (check session state)
    session = vault.store.get_session(tokenize_resp.vault_session)
    assert session.disclosed_count == 1  # Should be 1, not 3
    assert session.disclosed_bytes == len("alice@example.com")  # Should be length once, not 3x
