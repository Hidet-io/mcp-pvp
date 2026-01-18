# Safe Email Sender Example

This example demonstrates **end-to-end PII protection** using mcp-pvp's deliver mode. It shows how an AI agent can safely send emails without ever seeing recipient addresses.

## 🎯 The Problem

**User request:** "Email alice@example.com with the Q4 report"

**Without PVP:**
```
User Input → LLM sees: "Email alice@example.com..." → Logs/Telemetry/Vectors
                ↓
          Email exposed at every step
```

**With PVP:**
```
User Input → Tokenized → LLM sees: "Email {{token}}..." → Tool executes
                             ↓
                    NO PII EXPOSURE
```

---

## 📊 Architecture: Data Flow Diagram

```
┌─────────────┐
│   User      │  "Email alice@example.com with Q4 report"
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│  PHASE 1: TOKENIZE (Before LLM)                         │
│                                                          │
│  Input:  "Email alice@example.com with Q4 report"       │
│           ─────────────┬────────────                    │
│                        │ PVP Vault                       │
│                        ▼                                 │
│  Output: "Email {{"pii_ref":"tkn_X","type":"EMAIL"}}   │
│           with Q4 report"                                │
│                                                          │
│  ✓ alice@example.com → Vault (encrypted storage)        │
│  ✓ Token reference returned                             │
└─────────────────────────────────────────────────────────┘
       │
       │ Redacted content only
       ▼
┌─────────────────────────────────────────────────────────┐
│  PHASE 2: LLM PLANNING (Zero PII Exposure)              │
│                                                          │
│  LLM sees: "Email {{token}} with Q4 report"             │
│                                                          │
│  LLM generates plan:                                     │
│  {                                                       │
│    "tool": "send_email",                                │
│    "args": {                                             │
│      "to": {{"pii_ref":"tkn_X","type":"EMAIL"}},      │
│      "subject": "Q4 Report",                            │
│      "body": "..."                                       │
│    }                                                     │
│  }                                                       │
│                                                          │
│  ✓ LLM never sees alice@example.com                     │
│  ✓ Token flows through prompt safely                    │
│  ✓ No PII in LLM context, logs, or vectors              │
└─────────────────────────────────────────────────────────┘
       │
       │ Tool plan with token
       ▼
┌─────────────────────────────────────────────────────────┐
│  PHASE 3: DELIVER (PII Injection + Execution)           │
│                                                          │
│  Agent sends tool plan to Vault                          │
│                                                          │
│  Vault operations:                                       │
│  1. Verify token "tkn_X" exists                         │
│  2. Check policy: EMAIL allowed for send_email?         │
│  3. Retrieve: "tkn_X" → alice@example.com               │
│  4. Inject into args: {"to": "alice@example.com"}       │
│  5. Execute tool locally                                 │
│  6. Return success (no raw PII in response)             │
│                                                          │
│  ✓ PII injected at tool boundary only                   │
│  ✓ Never returned to agent/LLM                          │
│  ✓ Policy enforced before disclosure                    │
│  ✓ Audit logged (without raw values)                    │
└─────────────────────────────────────────────────────────┘
       │
       │ Result: {"status": "sent"}
       ▼
┌─────────────┐
│  Agent      │  Success, no PII exposed
└─────────────┘
```

---

## 🔐 Security Guarantees

### What the LLM Never Sees

| Phase | LLM Sees | PII Location |
|-------|----------|-------------|
| **User Input** | `"Email {{token}} with Q4 report"` | Vault (encrypted) |
| **Planning** | `{"to": {"pii_ref":"tkn_X"}}` | Vault (encrypted) |
| **Execution** | `{"status": "sent"}` | Tool executor only |
| **Response** | `"Email sent successfully"` | Never exposed |

### PII Exposure Surface

```
Without PVP:
  LLM Context: ██████████ (100% exposed)
  Logs:        ██████████ (100% exposed)
  Vectors:     ██████████ (100% exposed)
  Tool:        ██████████ (100% exposed)

With PVP:
  LLM Context: ░░░░░░░░░░ (0% exposed - tokens only)
  Logs:        ░░░░░░░░░░ (0% exposed - audit IDs only)
  Vectors:     ░░░░░░░░░░ (0% exposed - tokens only)
  Tool:        ██████████ (100% exposed - necessary for execution)
                    ↑
                  Only at execution boundary,
                  never returned to agent
```

---

## 🚀 Complete Walkthrough

### Step 1: Setup Policy

Define what PII types can go to which tools:

```python
from mcp_pvp import Policy, SinkPolicy, PolicyAllow, PIIType, Vault

policy = Policy(
    sinks={
        "tool:send_email": SinkPolicy(
            allow=[
                PolicyAllow(
                    type=PIIType.EMAIL,
                    arg_paths=["to", "cc", "bcc"]  # Only these args
                )
            ]
        )
    }
)

vault = Vault(policy=policy)
```

**What this means:**
- ✅ EMAIL tokens can be disclosed to `send_email` tool
- ✅ Only in `to`, `cc`, `bcc` arguments
- ❌ EMAIL to any other tool: BLOCKED
- ❌ EMAIL in `subject` or `body`: BLOCKED

---

### Step 2: Tokenize User Input

**Input:** Raw user message with PII

```python
from mcp_pvp import TokenizeRequest, TokenFormat

user_input = "Email alice@example.com with the Q4 report"

tokenize_request = TokenizeRequest(
    content=user_input,
    token_format=TokenFormat.JSON,  # LLM-friendly JSON tokens
    include_caps=True,               # Include capabilities (deprecated in v0.2)
)

response = vault.tokenize(tokenize_request)
```

**Output:**

```python
# What you get back:
response.vault_session   # "vs_uw7Ckx..."
response.redacted        # "Email {{\"pii_ref\":\"tkn_sr...\",\"type\":\"EMAIL\"}} with Q4 report"
response.tokens          # [JSONToken(pii_ref="tkn_sr...", type="EMAIL", cap=None)]
response.stats.tokens_created  # 1
response.stats.detections      # 1
```

**Security Analysis:**

```
BEFORE tokenization:
  PII in memory: alice@example.com
  
AFTER tokenization:
  ✓ Vault storage: {"tkn_sr...": "alice@example.com"} (encrypted)
  ✓ LLM input:     "Email {{token}} with Q4 report"
  ✓ PII removed from agent context
  ✓ Session expires in 3600s (default TTL)
```

---

### Step 3: LLM Generates Tool Plan

**LLM receives redacted content:**

```
Prompt to LLM:
  "Email {{\"pii_ref\":\"tkn_sr...\",\"type\":\"EMAIL\"}} with Q4 report"
```

**LLM generates plan (simulation):**

```python
# In production, this comes from your LLM
# Here we simulate what the LLM would generate

token = response.tokens[0]

# LLM's tool plan:
tool_plan = {
    "tool": "send_email",
    "args": {
        "to": token.model_dump(by_alias=True),  # Pass token through
        "subject": "Q4 Report",
        "body": "Please find attached the Q4 report."
    }
}
```

**Security Analysis:**

```
LLM context window:
  ✗ alice@example.com          NOT PRESENT
  ✓ {"pii_ref":"tkn_sr..."}    Token reference only
  
LLM embeddings/vectors:
  ✗ alice@example.com          NOT PRESENT
  ✓ "Email {{token}} ..."      Redacted text only
  
LLM logs:
  ✗ alice@example.com          NOT PRESENT
  ✓ Token references           Safe to log
```

---

### Step 4: Deliver (Inject & Execute)

Agent sends tool plan to Vault for execution:

```python
from mcp_pvp import DeliverRequest, ToolCall

deliver_request = DeliverRequest(
    vault_session=response.vault_session,  # From step 2
    tool_call=ToolCall(
        name="send_email",
        args=tool_plan["args"]  # Args with token references
    )
)

deliver_response = vault.deliver(deliver_request)
```

**What happens inside `vault.deliver()`:**

```
1. Parse args for tokens:
   Found: {"to": {"pii_ref":"tkn_sr...","type":"EMAIL"}}

2. Validate session:
   ✓ Session vs_uw7Ckx... is valid (not expired)
   ✓ Token tkn_sr... exists in session

3. Check policy:
   Tool: send_email
   Arg path: to
   PII type: EMAIL
   ✓ Policy allows: EMAIL in send_email.to

4. Retrieve PII:
   tkn_sr... → alice@example.com

5. Inject into args:
   BEFORE: {"to": {"pii_ref":"tkn_sr..."}}
   AFTER:  {"to": "alice@example.com"}

6. Execute tool locally:
   send_email(to="alice@example.com", subject="...", body="...")

7. Return result (WITHOUT raw PII):
   {"status": "sent", "message_id": "msg_123"}
```

**Output:**

```python
deliver_response.delivered   # True
deliver_response.audit_id    # "aud_5-cdGB..."
deliver_response.tool_result # {"status": "sent", ...}
                            # ↑ No PII in response!
```

**Security Analysis:**

```
PII disclosure scope:
  ✓ Injected into tool executor (necessary for email send)
  ✗ NOT returned to agent
  ✗ NOT in deliver_response
  ✗ NOT in logs (audit ID only)
  
Agent sees:
  {"status": "sent", "message_id": "msg_123"}
  
Alice's email address:
  ✗ Not in agent memory
  ✗ Not in LLM context
  ✗ Not in response
  ✓ Used only by send_email tool
  ✓ Discarded after execution
```

---

## 🧪 Running the Example

```bash
cd examples/safe_email_sender
python example.py
```

**Expected output:**

```
=== Safe Email Sender Example ===

User input: 'Email alice@example.com with the Q4 report'

Vault session: vs_uw7Ckx_WgWsmk77HSaFBFw
Redacted (what LLM sees):
Email {{"pii_ref":"tkn_srJDjN96iSQSDF4i","type":"EMAIL","cap":null}} with the Q4 report

Tokens created: 1
Detections: 1

[... tool execution ...]

=== Key Points ===
✓ LLM never saw alice@example.com
✓ Only token flowed through prompt and plan
✓ Raw email injected locally at tool boundary
✓ Policy enforced before disclosure
✓ Disclosure audited (without raw PII)
```

---

## 🎓 Key Takeaways

### 1. Zero PII in LLM Context

**Before PVP:**
```python
llm_prompt = "Email alice@example.com with Q4 report"
# ↑ PII in prompt → vectors → logs → telemetry
```

**With PVP:**
```python
llm_prompt = "Email {{token_ref}} with Q4 report"
# ↑ No PII anywhere in agent/LLM pipeline
```

### 2. Policy as Code

Policies are declarative and auditable:

```python
policy = Policy(sinks={
    "tool:send_email": SinkPolicy(allow=[
        PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc", "bcc"])
    ]),
    "tool:log_event": SinkPolicy(allow=[]),  # No PII allowed
})
```

Any violation = `PolicyDeniedError` with audit trail.

### 3. Deliver Mode = Minimum Exposure

```
Alternative (resolve mode):
  Agent: "Give me the email"
  Vault: "alice@example.com"  ← PII in agent memory now
  
Deliver mode:
  Agent: "Execute send_email with token"
  Vault: [injects PII] → [executes tool] → "Done"
  Agent: "Done"  ← No PII ever reached agent
```

Deliver mode keeps PII inside the vault boundary.

### 4. Audit Without Exposure

All operations logged:

```python
Audit trail:
  Event: DELIVER
  Tool: send_email
  Disclosed: {"EMAIL": 1}
  Audit ID: aud_5-cdGB...
  
  ✗ Raw email NOT in logs
  ✓ Metadata and counts only
```

Compliance-ready logs without PII exposure.

---

## 🔄 Comparison: All Three Modes

### Tokenize Only (No Delivery)

```python
# Just redact for display
response = vault.tokenize(TokenizeRequest(
    content="Email alice@example.com",
    token_format=TokenFormat.TEXT
))
print(response.redacted)
# "Email [[PII:EMAIL:tkn_X]]"
```

**Use case:** Displaying user data safely (UI, logs)

### Resolve Mode (Get PII Back)

```python
# Agent explicitly requests PII
resolve_response = vault.resolve(ResolveRequest(
    vault_session=session_id,
    tokens=[{"ref": "tkn_X", "cap": capability}],
    sink=Sink(kind="tool", name="send_email")
))
# Returns: {"tkn_X": "alice@example.com"}
```

**Use case:** Agent needs PII for complex multi-step logic
**Risk:** PII now in agent memory

### Deliver Mode (Zero Return) ⭐ Recommended

```python
# Agent never sees PII
deliver_response = vault.deliver(DeliverRequest(
    vault_session=session_id,
    tool_call=ToolCall(name="send_email", args={"to": token})
))
# Returns: {"status": "sent"} - no PII
```

**Use case:** Direct tool execution (email, SMS, API calls)
**Risk:** Minimal - PII never leaves vault

---

## 🎯 Next Steps

### Extend the Example

1. **Multiple recipients:**
   ```python
   "Email alice@example.com and bob@example.com"
   → Two tokens generated
   → Both injected into `to` field
   ```

2. **Multiple PII types:**
   ```python
   "Email alice@example.com at phone 555-1234"
   → EMAIL and PHONE tokens
   → Different policy rules per type
   ```

3. **Real tool executor:**
   ```python
   class SendGridExecutor(ToolExecutor):
       def execute(self, tool_name: str, args: dict) -> Any:
           if tool_name == "send_email":
               return sendgrid.send(to=args["to"], ...)
   
   vault = Vault(policy=policy, executor=SendGridExecutor())
   ```

### Integration Patterns

- **HTTP API:** Use `mcp_pvp.bindings.http` for REST integration
- **MCP Server:** Use `mcp_pvp.bindings.mcp` for MCP protocol
- **Langchain:** Wrap tools with PVP vault
- **AutoGen:** Inject vault in agent executor

### Advanced Features

- **Capability expiration:** `ttl_seconds=300`
- **Run context binding:** Capabilities tied to workflow step
- **Disclosure limits:** `max_total_disclosed_bytes_per_step`
- **Custom detectors:** Implement `PIIDetector` interface

---

## 📚 Further Reading

- [Core Concepts](../../README.md#core-concepts)
- [Policy Configuration](../../README.md#policy-example)
- [Threat Model](../../README.md#threat-model-what-this-helps-with)
- [API Reference](../../README.md#usage)

---

## ⚖️ License

Apache-2.0 - See [LICENSE](../../LICENSE) for details.
