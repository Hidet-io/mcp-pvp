"""Safe email sender example demonstrating deliver mode."""

from mcp_pvp import (
    DeliverRequest,
    PIIType,
    Policy,
    PolicyAllow,
    SinkPolicy,
    TokenFormat,
    TokenizeRequest,
    ToolCall,
    Vault,
)


def main() -> None:
    """Run safe email sender example."""
    print("=== Safe Email Sender Example ===\n")

    # 1. Configure policy
    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(
                allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc", "bcc"])]
            )
        }
    )

    vault = Vault(policy=policy)

    # 2. Tokenize user input
    print("User input: 'Email alice@example.com with the Q4 report'\n")

    tokenize_request = TokenizeRequest(
        content="Email alice@example.com with the Q4 report",
        token_format=TokenFormat.JSON,
        include_caps=True,
    )

    tokenize_response = vault.tokenize(tokenize_request)

    print(f"Vault session: {tokenize_response.vault_session}")
    print(f"Redacted (what LLM sees):\n{tokenize_response.redacted}\n")
    print(f"Tokens created: {tokenize_response.stats.tokens_created}")
    print(f"Detections: {tokenize_response.stats.detections}\n")

    # 3. Simulate LLM generating tool plan (using token)
    # In reality, LLM would see redacted content and generate this
    token = tokenize_response.tokens[0]
    print(f"LLM generates tool plan with token: {token}\n")

    # 4. Deliver: inject PII and execute locally
    tool_call = ToolCall(
        name="send_email",
        args={
            "to": token.model_dump(by_alias=True),  # JSON token object
            "subject": "Q4 Report",
            "body": "Please find attached the Q4 report.",
        },
    )

    deliver_request = DeliverRequest(
        vault_session=tokenize_response.vault_session,
        tool_call=tool_call,
    )

    deliver_response = vault.deliver(deliver_request)

    print(f"Delivered: {deliver_response.delivered}")
    print(f"Audit ID: {deliver_response.audit_id}")
    print("\nTool result (stub):")
    print(deliver_response.tool_result)

    print("\n=== Key Points ===")
    print("✓ LLM never saw alice@example.com")
    print("✓ Only token flowed through prompt and plan")
    print("✓ Raw email injected locally at tool boundary")
    print("✓ Policy enforced before disclosure")
    print("✓ Disclosure audited (without raw PII)")


if __name__ == "__main__":
    main()
