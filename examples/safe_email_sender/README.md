# Safe Email Sender Example

This example demonstrates how to use mcp-pvp's **deliver mode** to safely send emails without the LLM ever seeing the recipient's email address.

## Scenario

User says: "Email alice@example.com with the Q4 report"

**Without PVP:** Email address flows through LLM prompt, logs, and telemetry.

**With PVP:** Email address is tokenized before LLM sees it. Only the token flows through the plan. Raw email is injected locally at execution time.

## Flow

### 1. Tokenize User Input

```python
from mcp_pvp import Vault, TokenizeRequest, TokenFormat, Policy

vault = Vault(policy=Policy())

request = TokenizeRequest(
    content="Email alice@example.com with the Q4 report",
    token_format=TokenFormat.JSON,
    include_caps=True,
)

response = vault.tokenize(request)
print(response.redacted)
# Output: "Email {"$pii_ref":"tkn_abc","type":"EMAIL","cap":"cap_..."} with the Q4 report"
```

### 2. LLM Generates Tool Plan (with tokens)

The LLM sees the redacted content and generates a plan:

```json
{
  "tool": "send_email",
  "args": {
    "to": {"$pii_ref": "tkn_abc", "type": "EMAIL", "cap": "cap_xyz"},
    "subject": "Q4 Report",
    "body": "Please find attached the Q4 report."
  }
}
```

### 3. Deliver (Inject & Execute Locally)

```python
from mcp_pvp import DeliverRequest, ToolCall

deliver_request = DeliverRequest(
    vault_session=response.vault_session,
    tool_call=ToolCall(
        name="send_email",
        args={
            "to": {"$pii_ref": "tkn_abc", "type": "EMAIL", "cap": "cap_xyz"},
            "subject": "Q4 Report",
            "body": "Please find attached the Q4 report."
        }
    )
)

deliver_response = vault.deliver(deliver_request)
# Vault injects raw email and executes tool locally
# Raw email NEVER returns to the agent/LLM
```

## Policy Configuration

```python
from mcp_pvp import Policy, SinkPolicy, PolicyAllow, PIIType

policy = Policy(
    sinks={
        "tool:send_email": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc", "bcc"])
            ]
        )
    }
)

vault = Vault(policy=policy)
```

## Running the Example

```bash
cd examples/safe_email_sender
python example.py
```

## Key Takeaways

1. **LLM never sees raw email:** Only tokens in prompts and plans
2. **Policy enforced locally:** Vault checks before disclosure
3. **Deliver mode minimizes exposure:** Raw email injected at tool boundary, not returned to agent
4. **Audit trail:** All disclosures logged (without raw values)

## Next Steps

- Try with multiple recipients
- Add phone numbers, addresses
- Integrate with real email service
- Deploy with HTTP binding for agent integration
