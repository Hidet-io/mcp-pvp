"""MCP tool server for PVP using official MCP Python SDK.

Vault session lifecycle is tied to the MCP connection via lifespan:
- When a client connects, a vault session is created automatically.
- Clients discover their vault session by reading the ``pvp://session`` resource.
- All tool calls transparently resolve PII tokens and re-tokenize results using
  that connection-scoped session — no hidden arguments required.
"""

import json
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, cast

import structlog
from mcp.server.fastmcp import FastMCP
from mcp.types import ContentBlock, TextContent

from mcp_pvp.models import Policy, TextToken, TokenFormat, TokenizeRequest
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

    def __init__(self, *args: Any, vault: Vault | None = None, **kwargs: Any) -> None:
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

        # ── Built-in tool: pvp_tokenize ──────────────────────────────────────
        # Tokenizes PII into the connection-scoped vault so clients don't need
        # a local vault instance — the token is usable immediately in tool calls.
        @self.tool(
            name="pvp_tokenize",
            description=(
                "Tokenize PII in 'content' into the connection vault session. "
                "Returns the redacted string and TEXT-format tokens. "
                "Pass the returned tokens to other tools instead of raw PII."
            ),
        )
        def _pvp_tokenize_tool(content: str) -> dict[str, Any]:
            vault_session = self._get_vault_session()
            if vault_session is None:
                # Direct call without MCP connection (e.g. unit tests) —
                # create an ad-hoc session for this tokenization request.
                session = self._vault.store.create_session()
                vault_session = session.session_id

            resp = self._vault.tokenize(
                TokenizeRequest(
                    content=content,
                    token_format=TokenFormat.TEXT,
                    vault_session=vault_session,
                )
            )
            return {
                "redacted": resp.redacted,
                "tokens": [t.to_text() for t in resp.tokens if isinstance(t, TextToken)],
            }

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

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_vault_session(self) -> str | None:
        """Return the vault session ID from the active connection's lifespan context.

        Returns ``None`` when called outside a live request context (e.g. direct
        unit-test invocations of ``call_tool``).
        """
        try:
            ctx = self.get_context()
            lifespan_ctx: PvpLifespanContext = ctx.request_context.lifespan_context
            return lifespan_ctx.vault_session
        except (ValueError, AttributeError):
            return None

    def _resolve_tokens(
        self, name: str, arguments: dict[str, Any], vault_session: str
    ) -> dict[str, Any]:
        """Resolve PII tokens in *arguments* and return the de-tokenized copy."""
        logger.info("resolving_tokens_for_tool", tool_name=name, vault_session=vault_session)
        replacements, disclosed_types = self._vault.resolve_tokens_in_args(
            args=arguments,
            vault_session=vault_session,
            tool_name=name,
            run=None,
        )
        resolved = cast("dict[str, Any]", self._vault.inject_pii_into_args(arguments, replacements))
        logger.info(
            "tokens_resolved_for_tool",
            tool_name=name,
            resolved_count=len(replacements),
            disclosed_types=disclosed_types,
        )
        return resolved

    def _retokenize_blocks(
        self, name: str, blocks: list[ContentBlock], vault_session: str
    ) -> tuple[list[ContentBlock], list[Any]]:
        """Tokenize PII in a list of ContentBlocks.

        Returns ``(tokenized_blocks, all_tokens)``.
        """
        tokenized_blocks: list[ContentBlock] = []
        all_tokens: list[Any] = []
        for block in blocks:
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
                        TextContent(type="text", text=json.dumps(tokenized_parsed))
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
        return tokenized_blocks, all_tokens

    def _retokenize_result(self, name: str, result: Any, vault_session: str) -> Any:
        """Scan *result* for PII and replace it with fresh tokens.

        Handles the three shapes FastMCP may return:
        - ``list[ContentBlock]``  — current FastMCP (≥1.2)
        - ``(list[ContentBlock], raw_data)`` tuple — older back-compat path
        - plain scalar / dict — unlikely but handled
        """
        logger.info("tokenizing_tool_result", tool_name=name, vault_session=vault_session)

        content_blocks: list[ContentBlock] | None = None
        raw_data: Any = None

        if isinstance(result, tuple) and len(result) == 2:
            content_blocks, raw_data = result
        elif isinstance(result, list):
            content_blocks = result

        if content_blocks is not None:
            tokenized_blocks, all_tokens = self._retokenize_blocks(
                name, content_blocks, vault_session
            )
            logger.info("tool_result_tokenized", tool_name=name, tokens_found=len(all_tokens))

            if raw_data is not None:
                tokenized_raw, _ = self._vault.tokenize_tool_result(
                    tool_result=raw_data,
                    vault_session=vault_session,
                    run=None,
                )
                return (tokenized_blocks, tokenized_raw)

            return tokenized_blocks

        # Plain non-list, non-tuple value (unlikely from FastMCP but handle it).
        tokenized_result, result_tokens = self._vault.tokenize_tool_result(
            tool_result=result,
            vault_session=vault_session,
            run=None,
        )
        logger.info("tool_result_tokenized", tool_name=name, tokens_found=len(result_tokens))
        return tokenized_result

    # ── Tool call override ────────────────────────────────────────────────────

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> Sequence[ContentBlock] | dict[str, Any]:
        """Resolve PII tokens in arguments, execute the tool, re-tokenize results.

        The vault session is read from the per-connection lifespan context — no
        ``_vault_session`` argument is needed or accepted from callers.
        """
        vault_session = self._get_vault_session()

        if vault_session:
            arguments = self._resolve_tokens(name, arguments, vault_session)

        logger.info("executing_tool", tool_name=name)
        result = await super().call_tool(name, arguments)

        if vault_session:
            return cast(
                "Sequence[ContentBlock] | dict[str, Any]",
                self._retokenize_result(name, result, vault_session),
            )

        return result
