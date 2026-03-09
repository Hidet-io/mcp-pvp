"""Example of FastPvpMCP with MCP-native vault session management.

Flow
----
1. Client connects  → server creates a vault session in lifespan (automatic).
2. Client reads     pvp://session resource  → receives vault_session_id.
3. Client tokenizes PII with that vault_session_id using mcp_pvp.vault.tokenize().
4. Client calls     send_email(to=<token>, ...)  — no hidden arguments.
5. Server resolves  token → real email before invoking the tool.
6. Server re-tokenizes the result before returning it to the client.
7. Client disconnects → lifespan closes, session ends.
"""

import asyncio
from typing import Any

import anyio
from mcp import ClientSession
from mcp.types import AnyUrl

from mcp_pvp.bindings.mcp.server import FastPvpMCP
from mcp_pvp.models import PIIType, Policy, PolicyAllow, SinkPolicy, TokenFormat, TokenizeRequest
from mcp_pvp.vault import Vault

# ── Server setup ──────────────────────────────────────────────────────────────

policy = Policy(
    sinks={
        # Sink ID format: "{kind}:{name}"
        "tool:send_email": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "from"]),
            ]
        ),
    }
)

vault = Vault(policy=policy)
mcp = FastPvpMCP(name="pvp-demo", vault=vault)


@mcp.tool()
def send_email(to: str, subject: str, body: str) -> dict[str, Any]:
    """Send an email (simulated).

    Args:
        to: Recipient email address (may arrive as a PII token).
        subject: Email subject.
        body: Email body.
    """
    print(f"\n[Tool] send_email called — to={to!r}  (real address, resolved by server)")
    return {
        "status": "sent",
        "to": to,          # server will re-tokenize this before it leaves
        "subject": subject,
        "timestamp": "2026-03-09T10:30:00Z",
    }


# ── Demo ──────────────────────────────────────────────────────────────────────

async def demo() -> None:
    """Run an in-process MCP client ↔ server demo."""

    # Wire the client and server together with anyio memory streams
    # (the same mechanism the SDK uses for stdio transport under the hood).
    server_to_client_send, server_to_client_recv = anyio.create_memory_object_stream(16)
    client_to_server_send, client_to_server_recv = anyio.create_memory_object_stream(16)

    async def run_server() -> None:
        await mcp._mcp_server.run(
            client_to_server_recv,      # server reads from client
            server_to_client_send,      # server writes to client
            mcp._mcp_server.create_initialization_options(),
            raise_exceptions=True,
        )

    async def run_client(cancel_fn) -> None:
        async with ClientSession(server_to_client_recv, client_to_server_send) as session:
            await session.initialize()

            # ── Step 1: Discover vault session ────────────────────────────
            # The server created this session automatically when we connected
            # (via the _pvp_lifespan hook). Reading pvp://session is the
            # standard MCP way to find out which session ID to use.
            resource_result = await session.read_resource(AnyUrl("pvp://session"))
            vault_session_id = resource_result.contents[0].text
            print(f"[Client] Vault session (from pvp://session resource): {vault_session_id}")

            # ── Step 2: Tokenize PII before sending it to a tool ──────────
            tokenize_resp = vault.tokenize(
                TokenizeRequest(
                    content="john.doe@example.com",
                    token_format=TokenFormat.TEXT,
                    vault_session=vault_session_id,   # tie tokens to this connection
                )
            )
            email_token = tokenize_resp.tokens[0].to_text()
            print(f"[Client] Email tokenized → {email_token}")

            # ── Step 3: Call the tool with clean arguments ─────────────────
            # No _vault_session argument — the server reads it from lifespan.
            print("\n[Client] Calling send_email with token (no hidden _vault_session arg)…")
            result = await session.call_tool(
                "send_email",
                {
                    "to": email_token,      # PII token, not the real address
                    "subject": "Hello!",
                    "body": "This is a test.",
                },
            )

            # ── Step 4: Inspect the (re-tokenized) result ─────────────────
            print("\n[Client] Result received:")
            for block in result.content:
                print(f"  {block.text}")

            print(
                "\n✓ The email address in the result is a token — "
                "PII never left the server in plaintext."
            )

        # Client context exited → streams closed → server run() returns
        cancel_fn()

    async with anyio.create_task_group() as tg:

        async def _run_client_then_cancel() -> None:
            await run_client(tg.cancel_scope.cancel)

        tg.start_soon(run_server)
        tg.start_soon(_run_client_then_cancel)


if __name__ == "__main__":
    asyncio.run(demo())

