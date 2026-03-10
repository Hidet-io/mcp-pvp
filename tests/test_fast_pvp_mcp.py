"""Unit tests for FastPvpMCP — MCP server with automatic PII protection."""

import json

import pytest
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import AnyUrl

from mcp_pvp.bindings.mcp.server import FastPvpMCP
from mcp_pvp.models import (
    PIIType,
    Policy,
    PolicyAllow,
    SinkPolicy,
)
from mcp_pvp.vault import Vault

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_server(policy: Policy | None = None) -> FastPvpMCP:
    """Return a FastPvpMCP with send_email and echo tools registered."""
    vault = Vault(policy=policy or Policy())
    mcp = FastPvpMCP(name="test-server", vault=vault)

    @mcp.tool()
    def send_email(to: str, subject: str, body: str = "") -> dict:
        return {"status": "sent", "to": to, "subject": subject}

    @mcp.tool()
    def echo(message: str) -> dict:
        return {"echo": message}

    return mcp


def _parse_direct_result(result: object) -> object:
    """Normalize FastMCP call_tool result to a plain Python value.

    FastMCP may return:
    - ``list[ContentBlock]``          — current format (≥1.2)
    - ``(list[ContentBlock], raw)``   — older tuple/back-compat format
    - raw scalar / dict               — unlikely but handled
    """
    if isinstance(result, tuple) and len(result) == 2:
        # (content_blocks, raw_data) — return the already-parsed raw_data
        return result[1]
    if isinstance(result, list) and result:
        return json.loads(result[0].text)
    if isinstance(result, str):
        return json.loads(result)
    return result


def email_policy() -> Policy:
    return Policy(
        sinks={
            "tool:send_email": SinkPolicy(allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["to"])])
        }
    )


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


def test_default_vault_is_created():
    mcp = FastPvpMCP(name="test")
    assert mcp.vault is not None
    assert isinstance(mcp.vault, Vault)


def test_custom_vault_is_stored():
    vault = Vault(policy=email_policy())
    mcp = FastPvpMCP(name="test", vault=vault)
    assert mcp.vault is vault


def test_pvp_tokenize_tool_registered():
    mcp = make_server()
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "pvp_tokenize" in tool_names


def test_pvp_session_resource_registered():
    mcp = make_server()
    resources = mcp._resource_manager.list_resources()
    uris = [str(r.uri) for r in resources]
    assert any("pvp" in u and "session" in u for u in uris)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


def test_policy_getter():
    p = email_policy()
    mcp = FastPvpMCP(name="test", vault=Vault(policy=p))
    assert mcp.policy is p


def test_policy_setter():
    mcp = FastPvpMCP(name="test")
    new_policy = email_policy()
    mcp.policy = new_policy
    assert mcp.policy is new_policy
    assert mcp.vault.policy is new_policy


def test_vault_setter():
    mcp = FastPvpMCP(name="test")
    new_vault = Vault(policy=email_policy())
    mcp.vault = new_vault
    assert mcp.vault is new_vault


# ---------------------------------------------------------------------------
# pvp_tokenize — direct call (no vault session context)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pvp_tokenize_direct_call():
    """pvp_tokenize works when called with an explicit vault session."""
    mcp = make_server(email_policy())
    # Create a session directly in the vault
    session = mcp.vault.store.create_session()

    result = await mcp.call_tool(
        "pvp_tokenize",
        {"content": "email alice@example.com", "vault_session": session.session_id},
    )
    data = _parse_direct_result(result)
    assert "redacted" in data
    assert "tokens" in data
    assert "[[PII:EMAIL:" in data["redacted"]
    assert len(data["tokens"]) == 1


@pytest.mark.asyncio
async def test_pvp_tokenize_no_pii():
    """pvp_tokenize returns empty token list when no PII is found."""
    mcp = make_server()
    session = mcp.vault.store.create_session()

    result = await mcp.call_tool(
        "pvp_tokenize",
        {"content": "hello world", "vault_session": session.session_id},
    )
    data = _parse_direct_result(result)
    assert data["redacted"] == "hello world"
    assert data["tokens"] == []


# ---------------------------------------------------------------------------
# call_tool fallback: no lifespan context (direct / unit-test invocation)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_without_session_passthrough():
    """Tools invoked without a lifespan context return results unchanged."""
    mcp = make_server()

    result = await mcp.call_tool("echo", {"message": "hello"})
    data = _parse_direct_result(result)
    assert data["echo"] == "hello"


@pytest.mark.asyncio
async def test_call_tool_no_session_raw_email_not_tokenized():
    """Without a vault session the email passes through as-is (no protection)."""
    mcp = make_server(email_policy())

    result = await mcp.call_tool(
        "send_email",
        {"to": "alice@example.com", "subject": "test"},
    )
    data = _parse_direct_result(result)
    # No session → no tokenization of result
    assert data["to"] == "alice@example.com"


# ---------------------------------------------------------------------------
# Full in-process client ↔ server flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_process_session_resource():
    """Client can read pvp://session and gets a valid session ID."""
    mcp = make_server()

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        vsid = resource.contents[0].text

    assert vsid.startswith("vs_")
    stored = mcp.vault.store.get_session(vsid)
    assert stored is not None


@pytest.mark.asyncio
async def test_in_process_pvp_tokenize_tool():
    """pvp_tokenize called via the MCP protocol creates tokens in the server vault."""
    mcp = make_server(email_policy())

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        vsid = resource.contents[0].text

        tok_result = await session.call_tool(
            "pvp_tokenize",
            {"content": "contact bob@example.com", "vault_session": vsid},
        )
        data = json.loads(tok_result.content[0].text)

    assert "[[PII:EMAIL:" in data["redacted"]
    assert len(data["tokens"]) == 1
    token_text = data["tokens"][0]
    assert token_text.startswith("[[PII:EMAIL:")

    # Token must resolve in the server vault
    ref = token_text.removeprefix("[[PII:EMAIL:").rstrip("]").rstrip("]")
    stored_session = mcp.vault.store.get_session(vsid)
    assert ref in stored_session.tokens


@pytest.mark.asyncio
async def test_in_process_token_resolution_and_result_retokenization():
    """Full flow: tokenize → call tool → result contains retokenized PII."""
    mcp = make_server(email_policy())

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        vsid = resource.contents[0].text

        tok = await session.call_tool(
            "pvp_tokenize",
            {"content": "alice@example.com", "vault_session": vsid},
        )
        token = json.loads(tok.content[0].text)["tokens"][0]

        send = await session.call_tool("send_email", {"to": token, "subject": "Hi"})
        result = json.loads(send.content[0].text)

    assert "alice@example.com" not in str(result)
    assert "[[PII:EMAIL:" in result["to"]
    assert result["status"] == "sent"


@pytest.mark.asyncio
async def test_in_process_no_pii_args_passthrough():
    """Tools with no PII tokens in args resolve and return cleanly."""
    mcp = make_server()

    async with create_connected_server_and_client_session(mcp) as session:
        echo_result = await session.call_tool("echo", {"message": "no PII here"})
        data = json.loads(echo_result.content[0].text)

    assert data["echo"] == "no PII here"


@pytest.mark.asyncio
async def test_in_process_policy_denial():
    """Token in a disallowed argument path raises an error response."""
    mcp = make_server(email_policy())

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        vsid = resource.contents[0].text

        tok = await session.call_tool(
            "pvp_tokenize",
            {"content": "alice@example.com", "vault_session": vsid},
        )
        token = json.loads(tok.content[0].text)["tokens"][0]

        # Pass token in 'body' — not allowed by policy
        send = await session.call_tool(
            "send_email",
            {"to": "someone@example.com", "subject": "Hi", "body": token},
        )
        is_error = send.isError

    assert is_error is True


@pytest.mark.asyncio
async def test_in_process_each_connection_gets_own_session():
    """Two sequential connections produce different vault sessions."""
    mcp = make_server()
    sessions = []

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        sessions.append(resource.contents[0].text)

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        sessions.append(resource.contents[0].text)

    assert len(sessions) == 2
    assert sessions[0] != sessions[1]


@pytest.mark.asyncio
async def test_in_process_multiple_pii_tokenized_in_result():
    """Tool result with multiple PII strings has all of them retokenized."""
    policy = Policy(
        sinks={
            "tool:multi_pii": SinkPolicy(
                allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["query"])]
            )
        }
    )
    vault = Vault(policy=policy)
    mcp = FastPvpMCP(name="test-multi", vault=vault)

    @mcp.tool()
    def multi_pii(query: str) -> dict:
        return {
            "contact1": "alice@example.com",
            "contact2": "bob@example.com",
            "safe": "no pii",
        }

    async with create_connected_server_and_client_session(mcp) as session:
        resource = await session.read_resource(AnyUrl("pvp://session"))
        vsid = resource.contents[0].text

        tok = await session.call_tool(
            "pvp_tokenize", {"content": "alice@example.com", "vault_session": vsid}
        )
        token = json.loads(tok.content[0].text)["tokens"][0]

        r = await session.call_tool("multi_pii", {"query": token})
        data = json.loads(r.content[0].text)

    assert "alice@example.com" not in str(data)
    assert "bob@example.com" not in str(data)
    assert "[[PII:EMAIL:" in data["contact1"]
    assert "[[PII:EMAIL:" in data["contact2"]
    assert data["safe"] == "no pii"
