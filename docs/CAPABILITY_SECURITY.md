# Capability Security Design

## Overview

mcp-pvp uses HMAC-signed capabilities to control PII disclosure. As of v1.0, **all capabilities are sink-bound** to prevent capability reuse attacks.

## Security Principle

**Capabilities are weapons.** They must be:
1. **Issued on-demand** (not at tokenization time)
2. **Sink-specific** (bound to tool name + arg_path)
3. **Short-lived** (default: 5 minutes TTL)
4. **Single-use intent** (verified on every resolve/deliver)

---

## ⚠️ Security Issue (v0.1 - FIXED in v1.0)

### The Problem: Wildcard LOCAL Capabilities

**Before (v0.1):**
```python
# During tokenization - DANGEROUS!
cap = cap_manager.create(
    vault_session="vs_123",
    pii_ref="tkn_abc",
    pii_type=PIIType.EMAIL,
    sink=Sink(kind=SinkKind.LOCAL, name="local"),  # ❌ Wildcard!
    ttl_seconds=3600,
)
```

**Verification logic (v0.1):**
```python
# In caps.py verify()
if cap.sink.kind == SinkKind.LOCAL and cap.sink.name == "local":
    # Generic capability - can be used with any sink ❌ SECURITY HOLE!
    pass
```

### Attack Scenario

1. Agent tokenizes user email: `"Contact alice@example.com"`
2. Token returned with generic LOCAL capability
3. **Compromised orchestrator** or **prompt injection** attack:
   - Intended: `send_email(to=<token>)`  ← Safe, approved tool
   - Actual: `exfiltrate_to_attacker(data=<token>)`  ← Malicious!
4. **Capability reuse attack succeeds** because cap allows ANY sink

---

## ✅ Fixed Design (v1.0)

### No Capabilities at Tokenization

**Tokenize response (v1.0):**
```python
{
  "vault_session": "vs_123",
  "redacted": "Contact [[PII:EMAIL:tkn_abc]]",
  "tokens": [
    {
      "pii_ref": "tkn_abc",
      "type": "EMAIL",
      "cap": null  # ✅ No capability yet!
    }
  ]
}
```

### Capabilities Issued On-Demand

**Workflow:**

1. **Agent plans** tool call: `send_email(to="tkn_abc")`
2. **Vault issues** sink-specific capability:
   ```python
   cap = vault.issue_capability(
       vault_session="vs_123",
       pii_ref="tkn_abc",
       pii_type=PIIType.EMAIL,
       sink=Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to"),
       ttl_seconds=300,  # 5 minutes
   )
   ```
3. **Capability binds** to:
   - ✅ Tool name: `"send_email"`
   - ✅ Arg path: `"to"`
   - ✅ Session: `"vs_123"`
   - ✅ PII ref: `"tkn_abc"`
   - ✅ Expiration: 5 min from now

4. **Verification strict**:
   ```python
   # In caps.py verify() - v1.0
   if cap.sink.kind != sink.kind or cap.sink.name != sink.name:
       raise CapabilityInvalidError("sink mismatch")
   if cap.sink.arg_path != sink.arg_path:
       raise CapabilityInvalidError("arg_path mismatch")
   ```

### Attack Prevention

**Same attack attempt:**
```python
# Attacker tries to reuse capability for different tool
vault.resolve(
    tokens=[{"ref": "tkn_abc", "cap": cap}],
    sink=Sink(kind=SinkKind.TOOL, name="exfiltrate_to_attacker"),  # ❌ Different tool!
)
# Raises: CapabilityInvalidError("sink mismatch")
```

**Even same tool, different arg_path:**
```python
vault.resolve(
    tokens=[{"ref": "tkn_abc", "cap": cap}],
    sink=Sink(kind=SinkKind.TOOL, name="send_email", arg_path="bcc"),  # ❌ Different path!
)
# Raises: CapabilityInvalidError("arg_path mismatch")
```

---

## API Usage

### For Library Users

**Option 1: Use `deliver` mode (RECOMMENDED)**
```python
# No capability needed - vault handles everything
response = vault.deliver(
    DeliverRequest(
        vault_session="vs_123",
        tool_call={"name": "send_email", "args": {"to": "tkn_abc"}},
    )
)
# Vault issues capability internally, executes tool, returns sanitized result
```

**Option 2: Manual `resolve` with capability request**
```python
# Step 1: Issue capability for specific sink
cap = vault.issue_capability(
    vault_session="vs_123",
    pii_ref="tkn_abc",
    pii_type=PIIType.EMAIL,
    sink=Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to"),
)

# Step 2: Resolve with capability
response = vault.resolve(
    ResolveRequest(
        vault_session="vs_123",
        tokens=[{"ref": "tkn_abc", "cap": cap}],
        sink=Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to"),
    )
)
```

### For MCP Tool Users

**MCP tools automatically handle capability issuance:**

```javascript
// Claude Desktop - pvp.deliver (recommended)
{
  "name": "pvp.deliver",
  "arguments": {
    "vault_session": "vs_123",
    "tool_call": {
      "name": "send_email",
      "args": {"to": "tkn_abc"}
    }
  }
}
// Vault issues capability internally ✅
```

---

## Migration Guide (v0.1 → v1.0)

### Breaking Change

**If you were relying on capabilities in tokenize response:**

```python
# v0.1 (INSECURE - DO NOT USE)
tok_resp = vault.tokenize(TokenizeRequest(content="...", include_caps=True))
token = tok_resp.tokens[0]
cap = token.cap  # ❌ This is now None

# v1.0 (SECURE)
tok_resp = vault.tokenize(TokenizeRequest(content="..."))
token = tok_resp.tokens[0]
# Later, when you know the sink:
cap = vault.issue_capability(
    vault_session=tok_resp.vault_session,
    pii_ref=token.pii_ref,
    pii_type=token.type,
    sink=Sink(kind=SinkKind.TOOL, name="send_email", arg_path="to"),
)
```

### Recommended Approach

**Use `deliver` mode** - no manual capability management:

```python
# v1.0 (BEST PRACTICE)
tok_resp = vault.tokenize(TokenizeRequest(content="Email: alice@example.com"))
# ... agent plans tool call ...
deliver_resp = vault.deliver(
    DeliverRequest(
        vault_session=tok_resp.vault_session,
        tool_call={"name": "send_email", "args": {"to": "tkn_abc"}},
    )
)
# ✅ Capability issued internally, tool executed, result sanitized
```

---

## Capability Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. TOKENIZE                                                     │
│    ┌──────────────────┐                                         │
│    │ Content with PII │                                         │
│    └────────┬─────────┘                                         │
│             │                                                    │
│             v                                                    │
│    ┌──────────────────┐                                         │
│    │ Token (NO CAP)   │ ← Security: No capability yet!         │
│    │ pii_ref: tkn_abc │                                         │
│    │ cap: null        │                                         │
│    └──────────────────┘                                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 2. AGENT PLANNING                                               │
│    ┌─────────────────────────────┐                              │
│    │ LLM plans: send_email(to=X) │                              │
│    └─────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 3. CAPABILITY ISSUANCE (on-demand)                              │
│    ┌──────────────────────────────────────┐                     │
│    │ vault.issue_capability()             │                     │
│    │   + Policy check ✓                   │                     │
│    │   + Sink binding: send_email + to    │                     │
│    │   + TTL: 5 min                       │                     │
│    └────────────┬─────────────────────────┘                     │
│                 │                                                │
│                 v                                                │
│    ┌──────────────────────────────┐                             │
│    │ Capability (HMAC-signed)     │                             │
│    │ bound to:                    │                             │
│    │  - send_email tool           │                             │
│    │  - "to" arg_path             │                             │
│    │  - expires in 5 min          │                             │
│    └──────────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ 4. RESOLVE / DELIVER                                            │
│    ┌────────────────────────────┐                               │
│    │ Verify capability:         │                               │
│    │  ✓ HMAC signature          │                               │
│    │  ✓ Not expired             │                               │
│    │  ✓ Sink matches            │                               │
│    │  ✓ Arg path matches        │                               │
│    │  ✓ Session matches         │                               │
│    └────────────┬───────────────┘                               │
│                 │                                                │
│                 v                                                │
│    ┌────────────────────────────┐                               │
│    │ Disclosure approved ✓      │                               │
│    └────────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Properties

### ✅ Guaranteed Properties (v1.0)

1. **No capability reuse**: Capability bound to specific sink + tool + arg_path
2. **Time-limited**: Default 5 min TTL (configurable)
3. **Session-bound**: Cannot be used across sessions
4. **Policy-checked**: Capability only issued after policy approval
5. **Tamper-proof**: HMAC-SHA256 signature with constant-time verification

### ❌ Prevented Attacks

| Attack | v0.1 Status | v1.0 Status |
|--------|-------------|-------------|
| Capability reuse (different tool) | ❌ Possible | ✅ Blocked |
| Capability reuse (different arg_path) | ❌ Possible | ✅ Blocked |
| Prompt injection → tool switch | ❌ Vulnerable | ✅ Protected |
| HMAC tampering | ✅ Blocked | ✅ Blocked |
| Expired capability | ✅ Blocked | ✅ Blocked |
| Cross-session leakage | ✅ Blocked | ✅ Blocked |

---

## Implementation Notes

### Why Not JWT?

- **Simpler**: No JSON parsing in signature verification
- **Faster**: Direct HMAC with constant-time comparison
- **Sufficient**: We don't need JWT's features (public key, claims)
- **Explicit**: Clear capability structure in Pydantic models

### Why 5-Minute Default TTL?

- **Short enough**: Limits exposure window for leaked capabilities
- **Long enough**: Allows for normal agent workflow latency
- **Configurable**: Can be adjusted per-disclosure via `ttl_seconds`

### Why Bind arg_path?

Prevents attacks like:
```python
# Approved: send_email(to="alice@example.com")
# Attack: send_email(bcc="alice@example.com")  # Stealth copy!
```

Both use `send_email` tool, but different arg_paths have different privacy implications.

---

## Future Enhancements

### Potential Additions

1. **Capability revocation**: Explicit invalidation before expiration
2. **Usage tracking**: Count how many times capability was used
3. **Nonce-based**: One-time use capabilities
4. **Hierarchical scopes**: Capability attenuation chains

### NOT Planned

- **Public key crypto**: Adds complexity, no benefit for our use case
- **Wildcard capabilities**: Security anti-pattern, removed intentionally
- **Long-lived capabilities**: Defeats purpose of short TTL

---

## References

- [Capability-based security](https://en.wikipedia.org/wiki/Capability-based_security)
- [HMAC-SHA256](https://tools.ietf.org/html/rfc2104)
- [Principle of least privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)
