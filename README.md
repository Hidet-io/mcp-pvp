# mcp-pvp — Privacy Vault Protocol for MCP

**Tokenize sensitive data before the LLM sees it.**  
`mcp-pvp` is a lightweight security/runtime layer for MCP-based agents and workflows that prevents accidental leakage of PII and secrets by design.

> **Tokenize → Policy → Deliver → Audit**  
> Agents operate on *references*, not raw values.

Maintained by the team behind **Hidet** (hidet.io), and usable standalone.

---

## Why mcp-pvp

MCP makes tool calling easy. The hard part is **handling real user data safely**:
- emails, phone numbers, addresses
- API keys and tokens
- IDs, payment-like strings
- anything you should *not* put in an LLM prompt, logs, or telemetry

Most systems either:
- send raw values to an LLM (high risk), or
- do brittle redaction that breaks workflows (hard to restore safely)

`mcp-pvp` introduces a local **Privacy Vault** that stores sensitive values and issues **typed opaque tokens**. Tokens flow through prompts and tool plans. Raw values are **disclosed only when policy allows**, ideally via **deliver mode** so they never return to the agent/LLM.

> This is **not** a vulnerability scanner/fuzzer for MCP servers.  
> It’s a **privacy vault + policy enforcement runtime** for sensitive data in MCP workflows.

---

## Core concepts

### Tokens (references, not values)

**Text token** (LLM-safe):
```

[[PII:EMAIL:tkn_a1b2c3]]

````

**JSON token object** (preferred for tool args):
```json
{ "$pii_ref": "tkn_a1b2c3", "type": "EMAIL", "cap": "cap_..." }
````

### Vault sessions

Tokens are scoped to a short-lived **vault session** (`vs_...`) with TTL.
A token is valid only inside its session.

### Capabilities (caps)

Even if an LLM tries to trick the system (“restore everything”), the vault requires a signed **capability** authorizing disclosure to a specific sink/field for a limited time.

### Sinks + policies

Policies are enforced **inside the vault**, with a default-deny stance:

* allow specific PII types
* only for specific tools (sinks)
* optionally restricted to argument paths (e.g., `to`, `email`)

### Deliver mode (recommended)

Instead of returning raw PII back to the cloud engine/agent, the vault **injects PII locally** into tool calls and executes them (or hands off to a trusted local runner).
This is the biggest reduction in leak surface.

---

## What you get (v0.1 scope)

* ✅ PII detection (regex-first, no heavy deps)
* ✅ Tokenization with typed opaque refs
* ✅ Local vault session store with TTL
* ✅ Policy enforcement (sink allow-lists + limits)
* ✅ Capabilities (HMAC-signed)
* ✅ Audit events (no raw values)
* ✅ MCP tool binding:

  * `pvp.tokenize`
  * `pvp.resolve` (fallback)
  * `pvp.deliver` (recommended)

---

## How it works (end-to-end)

### 1) Tokenize locally before any LLM call

Input:

```
Email me at mitiku@example.com
```

Tokenized:

```
Email me at [[PII:EMAIL:tkn_a1b2c3]]
```

Raw value (`mitiku@example.com`) stays inside the local vault.

### 2) LLM produces tool plan using tokens

```json
{
  "action": "send_email",
  "args": {
    "to": { "$pii_ref": "tkn_a1b2c3", "type": "EMAIL", "cap": "cap_..." },
    "subject": "Hello",
    "body": "..."
  }
}
```

### 3) Vault enforces policy + injects locally (deliver)

Vault validates:

* token exists & session is valid
* cap is valid & matches sink/field
* policy allows `EMAIL` for `tool:send_email` at `to`
* disclosure limits not exceeded

Then it injects the real email and executes the tool locally.

---

## Quickstart (conceptual)

> Implementation commands will be added as the v0.1 API stabilizes.

1. Start the vault (Python)
2. Call `pvp.tokenize` on user input before LLM prompting
3. Keep tokens in prompts and plans
4. Use `pvp.deliver` for tool execution requiring sensitive values
   (use `pvp.resolve` only if you must)

---

## Policy example

```json
{
  "sinks": {
    "tool:send_email": {
      "allow": [
        { "type": "EMAIL", "arg_paths": ["to", "cc", "bcc"] }
      ]
    },
    "tool:crm_upsert_contact": {
      "allow": [
        { "type": "EMAIL", "arg_paths": ["email"] },
        { "type": "PHONE", "arg_paths": ["phone"] }
      ]
    }
  },
  "defaults": { "allow": [] },
  "limits": {
    "max_disclosures_per_step": 50,
    "max_total_disclosed_bytes_per_step": 8192
  },
  "type_rules": {
    "CC": { "mode": "MASK" },
    "API_KEY": { "mode": "MASK" }
  }
}
```

---

## PII types (initial)

High-signal types for v0.1:

* `EMAIL` (tokenize)
* `PHONE` (tokenize; sanity-checked)
* `IPV4` (tokenize)
* `CC` (masked by default; optional tokenize with Luhn)
* `API_KEY` (masked by default; optional tokenize)

We intentionally avoid “names/addresses” in v0.1 (regex-only is too error-prone). Those can come later via heuristics or lightweight models.

---

## Threat model (what this helps with)

* Prompt injection: “print the user’s email”
* Accidental logging/telemetry leaks
* Token spoofing (LLM hallucinates `tkn_...`)
* Over-broad restoration (“give me the full mapping”)
* Unsafe tool exfiltration (policy + deliver reduces exposure)

> No library can fully protect a compromised device.
> `mcp-pvp` minimizes common leakage paths and enforces least-privilege disclosure.

---

## Roadmap

### v0.1

* PVP core: tokenize/resolve/deliver
* TTL store
* policy allow-lists + limits
* HMAC capabilities
* MCP server binding
* Example: “safe email sender” (LLM never sees recipient)

### v0.2+

* encrypted local persistence (sqlite)
* expanded detectors (IBAN, secrets, configurable patterns)
* richer audit queries
* optional proxy mode (secure existing agents without refactor)

---

## Contributing

We welcome:

* detector modules (high precision, low false positives)
* policy primitives and safe defaults
* examples (email, CRM, ticketing, file access)
* interoperability tests with MCP clients/servers
* threat model improvements

See `CONTRIBUTING.md` (to be added).

---

## License

Apache-2.0

---