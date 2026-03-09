"""MCP tool server for PVP using official MCP Python SDK.

Vault session lifecycle is tied to the MCP connection via lifespan:
- When a client connects, a vault session is created automatically.
- Clients discover their vault session by reading the ``pvp://session`` resource.
- All tool calls transparently resolve PII tokens and re-tokenize results using
  that connection-scoped session — no hidden arguments required.
"""

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncIterator, Sequence

import structlog
from mcp.server.fastmcp import FastMCP
from mcp.types import ContentBlock, TextContent

from mcp_pvp.models import Policy
from mcp_pvp.vault import Vault

logger = structlog.get_logger(__name__)


@dataclass
class PvpLifespanContext:
    """Per-connection state held in the MCP lifespan context."""

    vault_session: str


class FastPvpMCP(FastMCP):
    """FastMCP server with automatic PII tokenization/resolution per connection.

    On every MCP connection the server creates a dedicated vault session via the
    ``lifespan`` hook.  Clients read ``pvp://session`` to discover their session
    ID, use it to tokenize PII before calling tools, and receive back results
    where any PII is re-tokenized automatically.
    """

    def __init__(self, *args: Any, vault: Vault = None, **kwargs: Any) -> None:
        # Store vault before calling super so the lifespan can reference it.
        self._vault = vault or Vault()
        super().__init__(*args, lifespan=self._pvp_lifespan, **kwargs)

        # ── Resource: pvp://session ──────────────────────────────────────────
        # Clients read this once after connecting to get their vault session ID.
        @self.resource(
            "pvp://session",
            name="PVP Vault Session",
            description=(
                "The vault session ID for this MCP connection. "
                "Read this resource first, then pass the returned ID to "
                "vault.tokenize() when creating PII tokens. The server will "
                "automatically resolve those tokens in tool arguments and "
                "re-tokenize any PII in tool results."
            ),
            mime_type="text/plain",
        )
        def _pvp_session_resource() -> str:
            ctx = self.get_context()
            lifespan_ctx: PvpLifespanContext = ctx.request_context.lifespan_context
            return lifespan_ctx.vault_session

    # ── Lifespan ─────────────────────────────────────────────────────────────

    @asynccontextmanager
    async def _pvp_lifespan(self, app: FastMCP) -> AsyncIterator[PvpLifespanContext]:
        """Create a vault session when a client connects; clean up on disconnect."""
        session = self._vault.store.create_session()
        logger.info("pvp_connection_established", vault_session=session.session_id)
        try:
            yield PvpLifespanContext(vault_session=session.session_id)
        finally:
            logger.info("pvp_connection_closed", vault_session=session.session_id)

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def policy(self) -> Policy:
        """Get current policy."""
        return self._vault.policy

    @policy.setter
    def policy(self, new_policy: Policy) -> None:
        """Set new policy and update vault."""
        self._vault.policy = new_policy

    @property
    def vault(self) -> Vault:
        """Get vault instance."""
        return self._vault

    @vault.setter
    def vault(self, new_vault: Vault) -> None:
        """Set new vault instance."""
        self._vault = new_vault

    # ── Tool call override ────────────────────────────────────────────────────

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[ContentBlock] | dict[str, Any]:
        """Resolve PII tokens in arguments, execute the tool, re-tokenize results.

        The vault session is read from the per-connection lifespan context — no
        ``_vault_session`` argument is needed or accepted from callers.

        Steps:
        1. Read vault session from lifespan context (set on connection by ``_pvp_lifespan``).
        2. Resolve any PII tokens in *arguments* to their real values.
        3. Execute the tool via FastMCP's default ``call_tool``.
        4. Scan the result for PII and replace it with fresh tokens.
        5. Return the tokenized result in the original FastMCP format.
        """
        # ── 1. Obtain vault session from the connection-scoped lifespan context ──
        vault_session: str | None = None
        try:
            ctx = self.get_context()
            lifespan_ctx: PvpLifespanContext = ctx.request_context.lifespan_context
            vault_session = lifespan_ctx.vault_session
        except (ValueError, AttributeError):
            # No active request context — tool was called directly (e.g. unit tests).
            pass

        # ── 2. Resolve tokens in arguments ───────────────────────────────────
        if vault_session:
            logger.info(
                "resolving_tokens_for_tool",
                tool_name=name,
                vault_session=vault_session,
            )
            replacements, disclosed_types = self._vault.resolve_tokens_in_args(
                args=arguments,
                vault_session=vault_session,
                tool_name=name,
                run=None,
            )
            arguments = self._vault.inject_pii_into_args(arguments, replacements)
            logger.info(
                "tokens_resolved_for_tool",
                tool_name=name,
                resolved_count=len(replacements),
                disclosed_types=disclosed_types,
            )

        # ── 3. Execute the tool ──────────────────────────────────────────────
        logger.info("executing_tool", tool_name=name)
        result = await super().call_tool(name, arguments)

        # ── 4. Re-tokenize result to prevent PII leakage ─────────────────────
        if vault_session:
            logger.info("tokenizing_tool_result", tool_name=name, vault_session=vault_session)
            all_tokens = []

            # FastMCP may return a tuple (content_blocks, raw_data).
            if isinstance(result, tuple) and len(result) == 2:
                content_blocks, raw_data = result

                tokenized_blocks = []
                if isinstance(content_blocks, list):
                    for block in content_blocks:
                        if isinstance(block, TextContent) and block.text:
                            try:
                                parsed = json.loads(block.text)
                                tokenized_parsed, tokens = self._vault.tokenize_tool_result(
                                    tool_result=parsed,
                                    vault_session=vault_session,
                                    run=None,
                                )
                                all_tokens.extend(tokens)
                                tokenized_blocks.append(
                                    TextContent(type="text", text=json.dumps(tokenized_parsed, indent=2))
                                )
                            except (json.JSONDecodeError, TypeError):
                                tokenized_text, tokens = self._vault.tokenize_tool_result(
                                    tool_result=block.text,
                                    vault_session=vault_session,
                                    run=None,
                                )
                                all_tokens.extend(tokens)
                                tokenized_blocks.append(TextContent(type="text", text=tokenized_text))
                        else:
                            tokenized_blocks.append(block)
                else:
                    tokenized_blocks = content_blocks

                tokenized_raw_data, tokens = self._vault.tokenize_tool_result(
                    tool_result=raw_data,
                    vault_session=vault_session,
                    run=None,
                )
                all_tokens.extend(tokens)

                logger.info("tool_result_tokenized", tool_name=name, tokens_found=len(all_tokens))
                return (tokenized_blocks, tokenized_raw_data)

            # Non-tuple fallback (e.g. direct calls returning plain values).
            tokenized_result, result_tokens = self._vault.tokenize_tool_result(
                tool_result=result,
                vault_session=vault_session,
                run=None,
            )
            logger.info("tool_result_tokenized", tool_name=name, tokens_found=len(result_tokens))
            return tokenized_result

        # No vault session — return result unchanged.
        return result