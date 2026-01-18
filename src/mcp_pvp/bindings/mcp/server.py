"""MCP tool server for PVP using official MCP Python SDK.

Exposes pvp.tokenize, pvp.resolve, and pvp.deliver as real MCP tools.
"""

from typing import Any

import structlog
from mcp.server.fastmcp import FastMCP

from mcp_pvp.models import (
    DeliverRequest,
    DeliverResponse,
    Policy,
    ResolveRequest,
    ResolveResponse,
    TokenFormat,
    TokenizeRequest,
    TokenizeResponse,
)
from mcp_pvp.vault import Vault

logger = structlog.get_logger(__name__)

# Initialize vault with default policy
_policy = Policy()
_vault = Vault(policy=_policy)

# Create MCP server
mcp = FastMCP("PVP - Privacy Vault Protocol")


@mcp.tool()
def tokenize(
    content: str,
    token_format: str = "JSON",
    include_caps: bool = True,
    session_ttl_seconds: int = 3600,
) -> dict[str, Any]:
    """Tokenize content containing PII/secrets before LLM sees it.

    Args:
        content: Content to tokenize
        token_format: Token format (TEXT or JSON)
        include_caps: Whether to include capabilities in response
        session_ttl_seconds: Session TTL in seconds

    Returns:
        Tokenization response with tokens and vault session
    """
    request = TokenizeRequest(
        content=content,
        token_format=TokenFormat(token_format),
        include_caps=include_caps,
        session_ttl_seconds=session_ttl_seconds,
    )
    response = _vault.tokenize(request)
    return response.model_dump(mode="json")


@mcp.tool()
def resolve(
    vault_session: str,
    tokens: list[dict[str, str]],
    sink: dict[str, Any],
) -> dict[str, Any]:
    """Resolve tokens to raw values (with policy enforcement).

    SECURITY: This operation enforces the PVP policy and validates capabilities.
    Use pvp.deliver instead if possible - it's safer and never returns PII to the LLM.

    Args:
        vault_session: Vault session ID
        tokens: List of token references with capabilities
        sink: Sink specification (kind, name, arg_path)

    Returns:
        Resolution response with raw values
    """
    request = ResolveRequest(
        vault_session=vault_session,
        tokens=tokens,
        sink=sink,
    )
    response = _vault.resolve(request)
    return response.model_dump(mode="json")


@mcp.tool()
def deliver(
    vault_session: str,
    tool_call: dict[str, Any],
) -> dict[str, Any]:
    """Inject PII into tool call and execute locally (RECOMMENDED - most secure).

    This is the recommended mode: PII never leaves the vault, is injected locally,
    and the sanitized response is returned to the LLM.

    Args:
        vault_session: Vault session ID
        tool_call: Tool call specification (name, args)

    Returns:
        Delivery response with executed result
    """
    request = DeliverRequest(
        vault_session=vault_session,
        tool_call=tool_call,
    )
    response = _vault.deliver(request)
    return response.model_dump(mode="json")


def main() -> None:
    """Run MCP server with stdio transport."""
    # Configure structured logging
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
    )

    logger.info("mcp_pvp_server_starting", transport="stdio")
    
    # Run with stdio transport (default for MCP)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
