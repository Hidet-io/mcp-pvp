# Privacy Vault Protocol (PVP) v1 — Specification

**Project:** mcp-pvp  
**Status:** Draft (v1)  
**Scope:** Local-first tokenization of sensitive data, policy-gated disclosure, and “deliver mode” injection for MCP tool calls.

> **Tokenize → Policy → Deliver → Audit**  
> Agents and LLMs operate on **references**, not raw values.

---

## 1. Motivation

MCP-based agents frequently handle sensitive inputs (PII, secrets). Sending raw values into LLM prompts, logs, telemetry, or cloud orchestration increases the risk of leakage.

PVP defines a local-first protocol where:
- sensitive values are replaced with typed opaque tokens,
- raw values are stored only in a local vault session,
- disclosure is allowed only to approved sinks under policy,
- **deliver mode** injects sensitive values locally at the tool boundary so raw values never return to the agent/LLM.

---

## 2. Definitions

### 2.1 Vault
A local service responsible for:
- detecting sensitive spans (PII/secrets),
- replacing them with tokens,
- storing raw values in a short-lived session,
- enforcing disclosure policies,
- auditing tokenization/disclosure actions,
- optionally executing or dispatching tool calls (deliver mode).

### 2.2 Vault Session (`vault_session`)
A scope container for tokens. Tokens are valid only within a session.

Properties:
- **unguessable** identifier (e.g., `vs_...`)
- **TTL-based** (expires automatically)
- optionally bound to workflow run/step context

### 2.3 Token Reference (`pii_ref`)
An opaque identifier (e.g., `tkn_...`) representing a stored sensitive value inside a vault session.

### 2.4 Sink
A destination where sensitive values may be disclosed/delivered:
- `tool`: a named tool invocation (preferred)
- `engine`: a cloud workflow engine/orchestrator (default deny)
- `llm`: a model prompt/response pipeline (default deny)

### 2.5 Capability (`cap`)
A signed authorization blob that permits disclosure/delivery of a specific token to a specific sink/argument path for a limited time.

Capabilities are the primary defense against:
- prompt injection (“restore everything”)
- token spoofing (LLM hallucinating `tkn_...`)
- over-broad restoration requests

---

## 3. Token Formats

PVP defines two standard token representations.

### 3.1 Text Token (LLM-safe)
```

[[PII:<TYPE>:<REF>]]

```

Example:
```

[[PII:EMAIL:tkn_a1b2c3]]

```

### 3.2 JSON Token Object (preferred for tool args)
```json
{ "$pii_ref": "tkn_a1b2c3", "type": "EMAIL", "cap": "cap_..." }
```

Rules:

* `type` is informational; the vault uses stored metadata + capability claims.
* `cap` is **RECOMMENDED** and in most deployments treated as **REQUIRED** for any disclosure.

---

## 4. PII Type Registry (v1)

Initial recommended types:

* `EMAIL`
* `PHONE`
* `IPV4`
* `CC` (credit card-like values)
* `API_KEY` (secret-like tokens)

### 4.1 Replacement Modes

Each type may be configured as:

* `TOKENIZE` (reversible): store raw value and return token
* `MASK` (irreversible default): return masked placeholder without storing raw

Recommended defaults:

* `EMAIL`, `PHONE`, `IPV4`: `TOKENIZE`
* `CC`, `API_KEY`: `MASK` (tokenization allowed only if explicitly enabled)

---

## 5. Security Requirements (Normative)

A compliant vault **MUST**:

1. **Default deny** disclosure unless explicitly permitted by policy.
2. Deny disclosure to sink kinds `llm` and `engine` unless explicitly enabled.
3. Bind tokens to a `vault_session`; tokens **MUST NOT** be globally valid.
4. Enforce session TTL and reject expired sessions.
5. Not log raw sensitive values (audit only metadata).
6. Validate capabilities (if enabled): signature, expiration, and claim matches.
7. Enforce rate/size limits on disclosure to reduce exfiltration blast radius.

---

## 6. Policy Model

Policy evaluation occurs **inside the vault**.

### 6.1 Sink Allow-Lists

Policy rules allow specific types to be disclosed to specific tool sinks and optionally restrict to specific argument paths.

Example:

```json
{
  "sinks": {
    "tool:send_email": {
      "allow": [
        { "type": "EMAIL", "arg_paths": ["to", "cc", "bcc"] }
      ]
    }
  },
  "defaults": { "allow": [] }
}
```

### 6.2 Limits

Recommended limits (per workflow step):

* `max_disclosures_per_step`
* `max_total_disclosed_bytes_per_step`

The vault should track disclosures by `(workflow_run_id, step_id)` when provided.

---

## 7. Capability Format

### 7.1 Claims (JSON)

A capability binds token usage to a sink and (optionally) to run context.

```json
{
  "v": 1,
  "vault_session": "vs_...",
  "pii_ref": "tkn_...",
  "pii_type": "EMAIL",
  "sink": { "kind": "tool", "name": "send_email", "arg_path": "to" },
  "run": { "workflow_run_id": "wr_...", "step_id": "s2" },
  "exp": 1730000000
}
```

### 7.2 Encoding (recommended, lightweight)

* `cap = base64url(json_bytes) + "." + base64url(hmac_sha256(secret, json_bytes))`

Verification:

* signature matches
* `exp` not exceeded
* claims match requested sink/run constraints

---

## 8. Operations

PVP defines three primary operations:

* `tokenize`
* `resolve` (fallback)
* `deliver` (recommended)

All operations return an envelope:

### 8.1 Response Envelope

Success:

```json
{ "ok": true, "result": { ... }, "error": null }
```

Failure:

```json
{
  "ok": false,
  "result": null,
  "error": {
    "code": "ERR_POLICY_DENIED",
    "message": "Disclosure denied by policy",
    "details": { "rule": "tool:send_email allows EMAIL only for to/cc/bcc" }
  }
}
```

---

## 9. `tokenize`

### 9.1 Purpose

Detect sensitive spans in content, replace with tokens, and store raw values locally.

### 9.2 Request

```json
{
  "vault_session": null,
  "content": "Contact me at mitiku@example.com",
  "content_type": "text/plain",
  "run": { "workflow_run_id": "wr_...", "step_id": "s1" },
  "policy_context": { "org_id": "org_...", "user_id": "u_..." },
  "options": {
    "token_format": "TEXT",
    "include_caps": true,
    "types": ["EMAIL", "PHONE", "IPV4", "CC", "API_KEY"]
  }
}
```

### 9.3 Result

```json
{
  "vault_session": "vs_01J...",
  "redacted": "Contact me at [[PII:EMAIL:tkn_a1]]",
  "tokens": [
    {
      "ref": "tkn_a1",
      "type": "EMAIL",
      "occurrences": 1,
      "caps": [
        {
          "sink": { "kind": "tool", "name": "send_email", "arg_path": "to" },
          "cap": "cap_..."
        }
      ]
    }
  ],
  "stats": { "EMAIL": 1 }
}
```

Notes:

* If `vault_session` is null, vault creates one.
* If a type is configured as `MASK`, vault may output a masked marker instead of issuing a token.

---

## 10. `resolve` (Selective Disclosure, fallback)

### 10.1 Purpose

Return raw values for specific token refs, only if permitted.

### 10.2 Request

```json
{
  "vault_session": "vs_01J...",
  "need": [
    { "ref": "tkn_a1", "cap": "cap_..." }
  ],
  "sink": { "kind": "tool", "name": "send_email", "arg_path": "to" },
  "run": { "workflow_run_id": "wr_...", "step_id": "s2" }
}
```

### 10.3 Result

```json
{
  "values": { "tkn_a1": "mitiku@example.com" },
  "audit_id": "aud_...",
  "disclosed": [
    { "ref": "tkn_a1", "type": "EMAIL", "bytes": 17 }
  ]
}
```

Security stance:

* Prefer `deliver` over `resolve` so raw PII does not transit back to agents/cloud.

---

## 11. `deliver` (Preferred)

### 11.1 Purpose

Safely inject sensitive values into tool calls locally under policy and capability checks.

### 11.2 Request

```json
{
  "vault_session": "vs_01J...",
  "tool_call": {
    "name": "send_email",
    "args": {
      "to": { "$pii_ref": "tkn_a1", "type": "EMAIL", "cap": "cap_..." },
      "subject": "Hello",
      "body": "..."
    }
  },
  "run": { "workflow_run_id": "wr_...", "step_id": "s3" }
}
```

### 11.3 Result

```json
{
  "delivered": true,
  "tool_result": { "message_id": "m_..." },
  "audit_id": "aud_..."
}
```

Behavior:

* For each token object in args:

  * validate session + token existence
  * validate cap (if enabled)
  * validate policy for `tool:<name>` at the argument path
  * enforce limits
* Inject raw values just-in-time at the tool boundary.
* Never log raw values.

Execution model:

* Vault may execute tools itself or dispatch to a trusted local runner.

---

## 12. Error Codes (Standard)

* `ERR_INVALID_REQUEST`
* `ERR_UNAUTHENTICATED`
* `ERR_UNAUTHORIZED`
* `ERR_VAULT_SESSION_UNKNOWN`
* `ERR_VAULT_SESSION_EXPIRED`
* `ERR_TOKEN_UNKNOWN`
* `ERR_CAP_INVALID`
* `ERR_CAP_EXPIRED`
* `ERR_POLICY_DENIED`
* `ERR_LIMIT_EXCEEDED`
* `ERR_INTERNAL`

---

## 13. Audit Events

A compliant implementation should emit audit events locally (no raw values), including:

* `TOKENIZE`: counts by type, session id, run context
* `RESOLVE`: sink/tool, arg_path, types disclosed, allowed/denied
* `DELIVER`: tool name, arg_paths injected, types disclosed, allowed/denied

Audit entries should include correlation fields when available:

* `vault_session`
* `workflow_run_id`
* `step_id`
* `audit_id`

---

## 14. Detection Engines

PVP does not mandate a specific detection engine. Implementations may use:

* **Microsoft Presidio** (recommended default when installed)
* a lightweight regex fallback for environments without Presidio

Regardless of detector:

* disclosure and delivery semantics remain the same
* masking/tokenization modes per type must be enforced consistently

---

## 15. Compatibility Notes

* The protocol is transport-agnostic and can be exposed via:

  * MCP tools: `pvp.tokenize`, `pvp.resolve`, `pvp.deliver`
  * HTTP endpoints (localhost binding recommended)
* All integrations should preserve token objects and avoid “restoring into prompts.”

---

## 16. Appendix: Minimal End-to-End Example

1. Tokenize:

* input: `Email me at mitiku@example.com`
* redacted: `Email me at [[PII:EMAIL:tkn_a1]]`

2. LLM tool plan references token:

```json
{
  "action": "send_email",
  "args": { "to": { "$pii_ref": "tkn_a1", "type": "EMAIL", "cap": "cap_..." } }
}
```

3. Deliver injects locally and executes:

* returns tool result, not raw PII

```
{ "delivered": true, "tool_result": { "message_id": "m_123" } }
```

```
::contentReference[oaicite:0]{index=0}
```
