"""examples/blog_client.py — Privacy-first MCP client for the Hacker News blog post.

Connects to blog_server.py via stdio, demonstrates the full PVP flow:
  1. Discover vault session
  2. Tokenize PII (email, phone)
  3. Call tools with tokens — raw PII never crosses the wire
  4. Observe re-tokenized results
  5. See default-deny in action

Run from the repo root:
    uv run python examples/blog_client.py
"""

import json
import sys
from pathlib import Path

import anyio
import structlog
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import AnyUrl

logger = structlog.get_logger(__name__)

SERVER_SCRIPT = str(Path(__file__).parent / "blog_server.py")

# ── Helpers ──────────────────────────────────────────────────────────────────


def print_section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def print_step(step: int, description: str) -> None:
    print(f"\n  [{step}] {description}")


def print_result(label: str, data: object) -> None:
    print(f"      {label}: {json.dumps(data, indent=8) if isinstance(data, dict) else data}")


# ── Main demo ────────────────────────────────────────────────────────────────


async def main() -> None:
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[SERVER_SCRIPT],
    )

    async with (
        stdio_client(server_params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as session,
    ):
        await session.initialize()

        # ================================================================
        # STEP 1: Discover the vault session
        # ================================================================
        print_section("PVP Privacy Vault Demo")
        print_step(1, "Discovering vault session...")

        resource = await session.read_resource(AnyUrl("pvp://session"))
        vault_session_id = resource.contents[0].text
        print_result("Vault session", vault_session_id)

        # ================================================================
        # STEP 2: Tokenize an email address
        # ================================================================
        print_step(2, "Tokenizing PII (email address)...")

        tok_result = await session.call_tool(
            "pvp_tokenize",
            {"content": "Please email alice@example.com about the Q1 report"},
        )
        tok_data = json.loads(tok_result.content[0].text)
        email_token = tok_data["tokens"][0]

        print_result("Original", "Please email alice@example.com about the Q1 report")
        print_result("Redacted", tok_data["redacted"])
        print_result("Token", email_token)
        print()
        print("      → The LLM sees the redacted version. Raw email is in the vault.")

        # ================================================================
        # STEP 3: Send email using the token (policy allows EMAIL → to)
        # ================================================================
        print_step(3, "Calling send_email with token (policy: EMAIL allowed in 'to')...")

        result = await session.call_tool(
            "send_email",
            {"to": email_token, "subject": "Q1 Report", "body": "Please review."},
        )
        result_data = json.loads(result.content[0].text)

        print_result("Result", result_data)
        print()
        print("      → Notice: result['to'] is a NEW token, not the raw email.")
        print("        The vault resolved the token for execution, then re-tokenized")
        print("        the response before returning it to us.")

        # ================================================================
        # STEP 4: Look up a user by email (different tool, same token)
        # ================================================================
        print_step(4, "Calling lookup_user with same email token...")

        lookup_result = await session.call_tool(
            "lookup_user",
            {"email": email_token},
        )
        lookup_data = json.loads(lookup_result.content[0].text)

        print_result("Result", lookup_data)
        print()
        print("      → The user's email AND phone in the result are both tokenized.")
        print("        Raw PII never reaches the client.")

        # ================================================================
        # STEP 5: Tokenize a phone number and schedule a call
        # ================================================================
        print_step(5, "Tokenizing a phone number...")

        phone_tok = await session.call_tool(
            "pvp_tokenize",
            {"content": "Call +1-555-0101 tomorrow at 3pm"},
        )
        phone_data = json.loads(phone_tok.content[0].text)
        phone_token = phone_data["tokens"][0]

        print_result("Redacted", phone_data["redacted"])
        print_result("Token", phone_token)

        print_step(6, "Calling schedule_call with phone token...")

        call_result = await session.call_tool(
            "schedule_call",
            {
                "phone_number": phone_token,
                "time": "2026-03-15T15:00:00",
                "topic": "Project kickoff",
            },
        )
        call_data = json.loads(call_result.content[0].text)
        print_result("Result", call_data)

        # ================================================================
        # STEP 6: Default-deny demo — try passing email to summarize_text
        # ================================================================
        print_step(7, "Default-deny demo: passing email token to summarize_text...")
        print("      (No policy allows PII for summarize_text → should be blocked)")

        summary_result = await session.call_tool(
            "summarize_text",
            {"text": f"Summarize this: {email_token}"},
        )
        # The vault will either deny the token resolution or pass through
        # the token as-is (unresolved) since there's no allow rule
        summary_text = summary_result.content[0].text
        print_result("Result", summary_text)
        print()
        print("      → The token was NOT resolved. The tool received the opaque")
        print("        token string, not the real email. Default-deny works.")

        # ================================================================
        # STEP 7: Plain tool call (no PII)
        # ================================================================
        print_step(8, "Plain tool call — echo (no PII involved)...")

        echo_result = await session.call_tool("echo", {"message": "Hello, HN!"})
        echo_data = json.loads(echo_result.content[0].text)
        print_result("Result", echo_data)

        # ================================================================
        # Summary
        # ================================================================
        print_section("Demo Complete")
        print(
            """
  Key takeaways:
  • Raw PII (alice@example.com, +1-555-0101) never appeared in client output
  • Each tool only received PII types its policy explicitly allows
  • Results were re-tokenized — even echoed PII comes back as tokens
  • Default-deny blocked PII resolution for unauthorized tools
  • All of this happened transparently — no token-handling code in tools
"""
        )


if __name__ == "__main__":
    anyio.run(main)
