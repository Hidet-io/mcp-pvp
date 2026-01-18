"""Integration tests for vault operations."""

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
    Vault,
)


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


def test_vault_deliver_mode() -> None:
    """Test vault deliver mode."""
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

    deliver_resp = vault.deliver(deliver_req)

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
