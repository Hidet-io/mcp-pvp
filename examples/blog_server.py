"""examples/blog_server.py — Privacy-first MCP server for the Hacker News blog post.

Demonstrates how FastPvpMCP protects PII across multiple tools with
fine-grained, per-tool, per-argument policy enforcement.

Run:
    uv run python examples/blog_server.py

Or let blog_client.py launch it as a subprocess automatically.
"""

import logging
import sys

import structlog

# ── Logging setup ────────────────────────────────────────────────────────────
# MCP stdio transport owns stdout. Redirect ALL logging to stderr so it
# doesn't corrupt the JSON-RPC stream.
logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
for handler in logging.root.handlers:
    handler.stream = sys.stderr

structlog.configure(
    processors=[structlog.dev.ConsoleRenderer()],
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)

from mcp_pvp.bindings.mcp.server import FastPvpMCP
from mcp_pvp.models import PIIType, Policy, PolicyAllow, PolicyLimits, SinkPolicy
from mcp_pvp.vault import Vault

logger = structlog.get_logger(__name__)

# ── Policy ───────────────────────────────────────────────────────────────────
# Declare exactly which PII types each tool may receive, and at which
# argument paths.  Everything else is default-deny.

policy = Policy(
    sinks={
        # send_email may see EMAIL tokens, but only in 'to' and 'cc'
        "tool:send_email": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc"]),
            ]
        ),
        # lookup_user may see EMAIL, but only in 'email'
        "tool:lookup_user": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.EMAIL, arg_paths=["email"]),
            ]
        ),
        # schedule_call may see PHONE, but only in 'phone_number'
        "tool:schedule_call": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.PHONE, arg_paths=["phone_number"]),
            ]
        ),
    },
    limits=PolicyLimits(
        max_disclosures_per_step=20,
        max_total_disclosed_bytes_per_step=4096,
    ),
)

vault = Vault(policy=policy)
mcp = FastPvpMCP(name="pvp-blog-demo", vault=vault)


# ── Tools ────────────────────────────────────────────────────────────────────
# Every @mcp.tool() is automatically wrapped by FastPvpMCP:
#   1. PII tokens in arguments are resolved (policy-checked)
#   2. The real tool function executes with real values
#   3. PII in the return value is re-tokenized before reaching the client


@mcp.tool()
def send_email(to: str, subject: str, body: str = "", cc: str = "") -> dict:
    """Send an email to a recipient.

    PII tokens in 'to' and 'cc' are resolved to real addresses by the vault.
    The response is re-tokenized so the client never sees raw email addresses.
    """
    logger.info("send_email called", to=to, subject=subject)
    return {
        "status": "sent",
        "to": to,
        "cc": cc or None,
        "subject": subject,
        "message_id": "msg_20260314_001",
    }


@mcp.tool()
def lookup_user(email: str) -> dict:
    """Look up a user by their email address.

    The email token is resolved, the lookup happens, and any PII
    in the result is re-tokenized automatically.
    """
    logger.info("lookup_user called", email=email)
    # Simulated database lookup
    users = {
        "alice@example.com": {
            "name": "Alice Johnson",
            "email": "alice@example.com",
            "role": "engineering",
            "phone": "+1-555-0101",
        },
        "bob@example.com": {
            "name": "Bob Smith",
            "email": "bob@example.com",
            "role": "sales",
            "phone": "+1-555-0202",
        },
    }
    user = users.get(email)
    if user:
        return {"found": True, **user}
    return {"found": False, "email": email}


@mcp.tool()
def schedule_call(phone_number: str, time: str, topic: str = "") -> dict:
    """Schedule a phone call.

    The phone number token is resolved by the vault.  Only PHONE type
    PII is allowed here — an EMAIL token in phone_number would be denied.
    """
    logger.info("schedule_call called", phone_number=phone_number, time=time)
    return {
        "status": "scheduled",
        "phone_number": phone_number,
        "time": time,
        "topic": topic,
        "call_id": "call_20260314_001",
    }


@mcp.tool()
def summarize_text(text: str) -> dict:
    """Summarize text. No PII policy — any tokens in 'text' will be denied.

    This demonstrates default-deny: since there's no policy allowing
    any PII type for this tool, passing a token here fails with PolicyDeniedError.
    """
    word_count = len(text.split())
    return {"summary": text[:100] + "..." if len(text) > 100 else text, "word_count": word_count}


@mcp.tool()
def echo(message: str) -> dict:
    """Simple echo — no PII involved, no vault interaction needed."""
    return {"echo": message}


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
