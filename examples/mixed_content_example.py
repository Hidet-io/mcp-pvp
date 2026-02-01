"""Example demonstrating mixed TEXT and JSON token formats in tool calls.

This example shows how the Vault can handle both:
- Structured JSON tokens: {"$pii_ref": "...", "type": "..."}
- Embedded TEXT tokens in strings: [[PII:TYPE:REF]]

This provides flexibility for LLMs to construct tool calls with PII in both
structured arguments and within freeform text.
"""

from typing import Any
from mcp_pvp import Vault, TokenizeRequest, DeliverRequest, ToolCall, Policy
from mcp_pvp.executor import ToolExecutor
from mcp_pvp.models import SinkPolicy, PolicyAllow, PIIType


def send_email(to: str, subject: str, body: str) -> str:
    """Simulated email sending function."""
    print(f"\n--- Email Being Sent ---")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")
    print(f"------------------------\n")
    return f"Email sent successfully to {to}"


class RealExecutor(ToolExecutor):
    def execute(self, tool_name: str, injected_args: dict[str, Any]) -> Any:
        if tool_name == "send_email":
            return send_email(**injected_args)
        raise ValueError(f"Unknown tool: {tool_name}")


# Configure policy to allow EMAIL disclosure to send_email tool
# Allow EMAIL in both 'to' arg and 'body' arg for mixed content
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

# Initialize vault
vault = Vault(policy=policy, executor=RealExecutor())

# Tokenize sensitive content containing both email and phone
request = TokenizeRequest(
    content="Email me at alice@example.com or call me at 555-123-4567"
)
tokenized = vault.tokenize(request)

print(f"Original content: {request.content}")
print(f"Redacted content: {tokenized.redacted}")
print(f"Tokens found: {len(tokenized.tokens)}")
for token in tokenized.tokens:
    print(f"  - {token.type}: {token.pii_ref}")

# Get tokens
email_token = tokenized.tokens[0]  # alice@example.com
phone_token = tokenized.tokens[1]  # 555-123-4567

# LLM creates tool call with MIXED content:
# - JSON token for structured 'to' argument
# - TEXT tokens embedded in the 'body' string
llm_tool_call = ToolCall(
    name="send_email",
    args={
        "to": {"$pii_ref": email_token.pii_ref, "type": email_token.type},
        "body": f"Hello! Please reply to [[PII:EMAIL:{email_token.pii_ref}]] or call [[PII:PHONE:{phone_token.pii_ref}]].",
        "subject": "Contact Request"
    }
)

print(f"\nLLM Tool Call (with tokens):")
print(f"  to: {llm_tool_call.args['to']}")
print(f"  body: {llm_tool_call.args['body']}")

# Vault delivers - replaces both JSON and TEXT tokens with real PII
delivery_request = DeliverRequest(
    vault_session=tokenized.vault_session,
    tool_call=llm_tool_call,
)
deliver_response = vault.deliver(delivery_request)

print(f"\nDelivery successful: {deliver_response.delivered}")
print(f"Tool result: {deliver_response.tool_result}")
print(f"Audit ID: {deliver_response.audit_id}")
