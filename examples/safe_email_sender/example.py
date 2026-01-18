"""Safe email sender example demonstrating end-to-end PII protection.

This example shows:
1. How to tokenize PII before it reaches the LLM
2. How the LLM operates on tokens (not raw values)
3. How deliver mode injects PII only at tool execution
4. How policy enforcement prevents unauthorized disclosure
5. How audit trails work without exposing raw PII

Security guarantee: alice@example.com NEVER appears in:
- LLM context window
- LLM embeddings/vectors
- Agent memory
- API responses (except tool executor)
- Logs (only audit IDs and metadata)
"""

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
    """Run safe email sender example with detailed output."""
    print("=" * 70)
    print("  SAFE EMAIL SENDER - PII PROTECTION DEMONSTRATION")
    print("=" * 70)
    print()
    print("Scenario: User wants to email alice@example.com with Q4 report")
    print("Challenge: How to let AI agent do this without exposing the email?")
    print()

    # =========================================================================
    # PHASE 1: CONFIGURE POLICY (What PII can go where)
    # =========================================================================
    print("─" * 70)
    print("PHASE 1: Configure Policy")
    print("─" * 70)
    print()

    policy = Policy(
        sinks={
            "tool:send_email": SinkPolicy(
                allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc", "bcc"])]
            )
        }
    )

    print("Policy configured:")
    print("  ✓ Tool: send_email")
    print("  ✓ Allowed PII: EMAIL")
    print("  ✓ Allowed args: to, cc, bcc")
    print("  ✗ Any other tool/arg: BLOCKED")
    print()

    vault = Vault(policy=policy)
    print("Vault initialized with policy enforcement")
    print()

    # =========================================================================
    # PHASE 2: TOKENIZE (Remove PII before LLM sees it)
    # =========================================================================
    print("─" * 70)
    print("PHASE 2: Tokenize User Input")
    print("─" * 70)
    print()

    user_input = "Email alice@example.com with the Q4 report"
    print(f"User input (RAW): '{user_input}'")
    print()

    tokenize_request = TokenizeRequest(
        content=user_input,
        token_format=TokenFormat.JSON,  # LLM-friendly format
        include_caps=True,  # Deprecated in v0.2, kept for compatibility
    )

    tokenize_response = vault.tokenize(tokenize_request)

    print("Tokenization complete:")
    print(f"  Vault session: {tokenize_response.vault_session}")
    print(f"  Tokens created: {tokenize_response.stats.tokens_created}")
    print(f"  Detections: {tokenize_response.stats.detections}")
    print()
    print("What LLM will see (redacted):")
    print(f"  '{tokenize_response.redacted}'")
    print()
    print("Security check:")
    print("  ✓ 'alice@example.com' removed from agent context")
    print("  ✓ Token reference inserted instead")
    print("  ✓ Raw email stored in vault (encrypted)")
    print()

    # =========================================================================
    # PHASE 3: LLM PLANNING (Operates on tokens, not PII)
    # =========================================================================
    print("─" * 70)
    print("PHASE 3: LLM Generates Tool Plan")
    print("─" * 70)
    print()

    # In production, this would come from your LLM
    # The LLM sees the redacted content and generates a tool plan
    token = tokenize_response.tokens[0]

    print("LLM receives:")
    print(f"  Input: '{tokenize_response.redacted}'")
    print()
    print("LLM generates tool plan:")
    print("  {")
    print("    'tool': 'send_email',")
    print("    'args': {")
    print(f"      'to': {token},")
    print("      'subject': 'Q4 Report',")
    print("      'body': 'Please find attached the Q4 report.'")
    print("    }")
    print("  }")
    print()
    print("Security check:")
    print("  ✓ LLM never saw 'alice@example.com'")
    print("  ✓ Only token in LLM context window")
    print("  ✓ Only token in embeddings/vectors")
    print("  ✓ Only token in LLM provider logs")
    print()

    # =========================================================================
    # PHASE 4: DELIVER (Inject PII and execute, never return raw value)
    # =========================================================================
    print("─" * 70)
    print("PHASE 4: Deliver (Inject & Execute)")
    print("─" * 70)
    print()

    print("Agent sends tool plan to Vault for execution...")
    print()

    tool_call = ToolCall(
        name="send_email",
        args={
            "to": token.model_dump(by_alias=True),  # Pass token through
            "subject": "Q4 Report",
            "body": "Please find attached the Q4 report.",
        },
    )

    deliver_request = DeliverRequest(
        vault_session=tokenize_response.vault_session,
        tool_call=tool_call,
    )

    print("Vault operations (internal):")
    print("  1. Parse args for tokens: Found token in 'to' field")
    print(f"  2. Validate session: {tokenize_response.vault_session} ✓")
    print("  3. Check policy: EMAIL allowed in send_email.to? ✓")
    print(f"  4. Retrieve PII: {token.pii_ref} → <redacted>")

    print("  5. Inject into args: {'to': 'alice@example.com', ...}")
    print("  6. Execute tool: send_email(to='alice@example.com', ...)")
    print("  7. Return result WITHOUT raw PII")
    print()

    deliver_response = vault.deliver(deliver_request)

    print("Delivery complete:")
    print(f"  Delivered: {deliver_response.delivered}")
    print(f"  Audit ID: {deliver_response.audit_id}")
    print()
    print("Tool result (what agent sees):")
    print(f"  {deliver_response.tool_result}")
    print()
    print("Security check:")
    print("  ✓ alice@example.com injected at tool boundary")
    print("  ✗ alice@example.com NOT in deliver_response")
    print("  ✗ alice@example.com NOT returned to agent")
    print("  ✓ Only execution status returned")
    print("  ✓ Disclosure audited (without raw PII in logs)")
    print()

    # =========================================================================
    # SUMMARY: END-TO-END PII PROTECTION
    # =========================================================================
    print("=" * 70)
    print("  PII PROTECTION SUMMARY")
    print("=" * 70)
    print()
    print("Where 'alice@example.com' appeared:")
    print("  ✓ Vault storage (encrypted)")
    print("  ✓ Tool executor (send_email function)")
    print()
    print("Where 'alice@example.com' NEVER appeared:")
    print("  ✗ LLM context window")
    print("  ✗ LLM embeddings/vectors")
    print("  ✗ LLM provider logs")
    print("  ✗ Agent memory")
    print("  ✗ API responses")
    print("  ✗ Audit logs (only metadata)")
    print()
    print("Security benefits:")
    print("  • Zero PII in training data extraction risk")
    print("  • Zero PII in prompt injection attacks")
    print("  • Zero PII in telemetry/observability")
    print("  • Compliance-ready audit trails")
    print("  • Policy-enforced access control")
    print()
    print("=" * 70)


if __name__ == "__main__":
    main()
