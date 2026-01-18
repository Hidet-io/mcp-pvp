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

## Installation

### Using uv (recommended)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/Spidux-ai/mcp-pvp.git
cd mcp-pvp

# Create virtual environment and install
uv venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
uv pip install -e ".[all]"

# Or use the Makefile
make install-all
```

### Using pip

```bash
# Basic installation (regex detector)
pip install mcp-pvp

# With Presidio detector (recommended)
pip install mcp-pvp[presidio]

# With HTTP binding
pip install mcp-pvp[http]

# All extras
pip install mcp-pvp[all]
```

### Quick Start with Makefile

Once installed with Poetry, use the Makefile for common tasks:

```bash
make help          # Show all available commands
make test          # Run tests
make lint          # Run linter
make format        # Format code
make check         # Run all checks (lint, format, typecheck, test)
make run-http      # Start HTTP API server
```

---

## Compatibility & Requirements

### Python Versions

- **Required**: Python 3.11+
- **Tested**: Python 3.11, 3.12
- **Not Supported**: Python 3.10 and below (uses modern type hints)

### MCP SDK

- **Required**: MCP SDK 1.25.0+
- **Tested with**: 1.25.x, 1.26.x
- **Note**: MCP protocol is evolving; ensure SDK compatibility

### Optional Dependencies (Extras)

Install extras based on your use case:

```bash
# Presidio detector (recommended for production)
pip install mcp-pvp[presidio]
```
- **What**: Microsoft Presidio for high-quality PII detection
- **When**: Production deployments, multi-language PII, advanced patterns
- **Fallback**: Regex detector (built-in, no extra deps)

```bash
# HTTP binding
pip install mcp-pvp[http]
```
- **What**: FastAPI + Uvicorn HTTP server
- **When**: Exposing vault as REST API, testing with curl/Postman
- **Includes**: FastAPI, Uvicorn with standard extras

```bash
# MCP executor (for real tool execution)
pip install mcp-pvp[mcp]
```
- **What**: MCP SDK for executing real tools in deliver mode
- **When**: Using `MCP_ToolExecutor` to call actual MCP tools
- **Note**: Already included in base dependencies

```bash
# All extras (everything)
pip install mcp-pvp[all]
```
- **What**: Presidio + HTTP + all optional features
- **When**: Full-featured development or deployment

```bash
# Development tools
pip install mcp-pvp[dev]
```
- **What**: pytest, ruff, mypy, pre-commit, build tools
- **When**: Contributing to mcp-pvp or running tests locally

### Platform Support

- **Linux**: Fully supported ✅
- **macOS**: Fully supported ✅
- **Windows**: Supported ⚠️ (Presidio may require WSL for some languages)

### Breaking Changes (0.x → 0.2)

If upgrading from 0.1.0, note these **BREAKING** changes:

1. **Capabilities no longer included at tokenization**
   - Old: `tokenize()` returned tokens with `.cap` field
   - New: `.cap` is `None` by default; issued on-demand in `resolve()`
   - **Migration**: If you relied on capabilities at tokenization, update to request capabilities explicitly or use `resolve()` 

2. **Wildcard LOCAL capabilities removed**
   - Old: Capabilities with `sink.kind=LOCAL, sink.name="local"` worked for any tool
   - New: Capabilities strictly bound to specific sink (tool + arg_path)
   - **Migration**: Capabilities are now sink-specific; reuse across tools blocked

3. **ToolExecutor required for deliver mode**
   - Old: `deliver()` returned stub responses
   - New: Requires `ToolExecutor` implementation (defaults to `DummyExecutor`)
   - **Migration**: Provide custom executor or accept stub responses

See [CHANGELOG.md](CHANGELOG.md) for detailed migration guide.

---

## Quick Start

### Library Usage

```python
from mcp_pvp import Vault, TokenizeRequest, DeliverRequest, ToolCall, Policy

# Initialize vault
vault = Vault(policy=Policy())

# Tokenize sensitive content
request = TokenizeRequest(content="Email me at alice@example.com")
response = vault.tokenize(request)

print(response.redacted)  # "Email me at [[PII:EMAIL:tkn_xyz]]"

# Use deliver mode (recommended)
deliver_response = vault.deliver(
    DeliverRequest(
        vault_session=response.vault_session,
        tool_call=ToolCall(name="send_email", args={...})
    )
)
```

### HTTP Server

```bash
# Start HTTP server (localhost:8765)
mcp-pvp-http

# Or with custom config
PVP_HTTP_PORT=9000 mcp-pvp-http
```

Then use the API:

```bash
curl -X POST http://localhost:8765/pvp/v1/tokenize \
  -H "Content-Type: application/json" \
  -d '{"content": "Email alice@example.com", "token_format": "JSON"}'
```

### MCP Tool Server

The MCP binding exposes `pvp.tokenize`, `pvp.resolve`, and `pvp.deliver` as real MCP tools using the official MCP Python SDK.

#### Running as MCP Server

```bash
# Start the MCP server with stdio transport
mcp-pvp-mcp
```

#### Integrating with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pvp": {
      "command": "mcp-pvp-mcp",
      "env": {}
    }
  }
}
```

#### Using with MCP Inspector

Test the server interactively:

```bash
# Install MCP Inspector
npx @modelcontextprotocol/inspector

# Connect to mcp-pvp server
# The inspector will prompt for the command: mcp-pvp-mcp
```

#### Available Tools

- **`pvp.tokenize`**: Tokenize sensitive content and return redacted text with capabilities
  ```json
  {
    "content": "Email: user@example.com",
    "token_format": "TEXT",
    "session_ttl_seconds": 3600
  }
  ```

- **`pvp.resolve`**: Resolve tokens back to original values (with capability verification)
  ```json
  {
    "vault_session": "vs_...",
    "tokens": [{"ref": "tkn_...", "cap": "eyJ..."}],
    "sink": {"kind": "tool", "name": "send_email"}
  }
  ```

- **`pvp.deliver`**: Inject PII into tool call args without returning raw values
  ```json
  {
    "vault_session": "vs_...",
    "tool_call": {
      "name": "send_email",
      "args": {"to": "EMAIL_TOKEN_001"}
    }
  }
  ```

## Usage

See [examples/safe_email_sender/](examples/safe_email_sender/) for a complete example.

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

## Feature Matrix & Differentiation

### Where mcp-pvp fits
There are great tools for *detecting* PII and great tools for *validating* LLM outputs, but fewer reusable building blocks for **MCP-native, local-first, policy-gated disclosure and safe tool execution**.

mcp-pvp is intentionally **not** a detector-only library.  
It’s a **Privacy Vault runtime** for MCP workflows: tokenize → policy → deliver → audit.

### Feature matrix

| Capability | **mcp-pvp (this project)** | **Microsoft Presidio** | **LangChain PII middleware** | **Guardrails / Portkey guardrails** | **Vault MCP Server (HashiCorp)** |
|---|---|---|---|---|---|
| High-quality PII detection | ✅ (via Presidio by default; pluggable) | ✅ | ✅ | ✅ | ❌ |
| Redaction / anonymization | ✅ (tokenization + masking strategies) | ✅ | ✅ | ✅ | ❌ |
| Local “vault session” storing raw PII | ✅ | ❌ | ⚠️ (framework-scoped) | ❌ (often service/gateway-scoped) | ✅ (but for *secrets*, not PII flows) |
| Typed opaque tokens in prompts/plans | ✅ | ⚠️ (anonymization placeholders, not MCP tokens) | ⚠️ | ⚠️ | ❌ |
| Capability-based selective disclosure | ✅ | ❌ | ❌ / limited | ❌ / varies | ✅ (Vault auth model, but for secrets APIs) |
| Per-tool / per-arg-path policy enforcement (“sink allow-lists”) | ✅ | ❌ | ⚠️ | ✅ (provider guardrails) | ✅ (Vault policy system for secrets) |
| **Deliver mode** (inject PII locally into tool calls so raw never returns to agent/LLM) | ✅ (key differentiator) | ❌ | ❌ | ❌ | ❌ (different use-case) |
| MCP-native integration (tools / proxy / middleware) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Framework-agnostic (works with any MCP client) | ✅ | ✅ | ❌ | ✅ | ✅ |
| Audit trail for disclosure (without raw values) | ✅ | ⚠️ | ⚠️ | ✅ | ✅ |

**Notes**
- Presidio excels at detection + anonymization, but it’s not a vault/session + disclosure protocol. 
- LangChain provides PII middleware that redacts before model calls and restores values for tool execution—conceptually close, but framework-tied and not MCP-native. 
- Guardrails ecosystems (Guardrails AI, Portkey guardrails) are great for validation/redaction pipelines, but they typically don’t provide a local vault + deliver-mode execution pattern.
- HashiCorp’s Vault MCP server integrates MCP with *secrets management* (credentials, mounts, policies). It’s complementary, not a replacement for PII-flow minimization.

---

### Differentiation (why mcp-pvp exists)

#### 1) Presidio-grade detection + MCP-native runtime
We use **Microsoft Presidio** as the default detection/anonymization engine, so we don’t reinvent detection quality. We focus on the missing layer: **MCP-native privacy runtime** that safely carries sensitive values through tool plans without leaking them. 

#### 2) Tokens are first-class (agents operate on references)
mcp-pvp replaces sensitive spans with **typed opaque tokens** (text + JSON forms). Tokens are scoped to a **vault session** with TTL, reducing replay and accidental reuse.

#### 3) Capabilities prevent “restore everything”
Even if an LLM is tricked (prompt injection) or hallucinates token IDs, disclosure requires **capabilities** that bind:
token + sink/tool + arg_path + expiration (+ optional run/step).

#### 4) Deliver mode eliminates a major exfiltration path
Most approaches do: redact → restore → call tool (raw PII passes through the agent/orchestrator).
mcp-pvp can do: **tokenize → plan with tokens → deliver locally**, injecting PII only at the tool boundary—so raw PII never returns to the agent/LLM.

#### 5) Policy enforcement lives where it must: locally
mcp-pvp enforces allow-lists and limits in the local vault (default deny), aligning with MCP ecosystem security best practices and reducing trust in cloud components.


## Observability & Monitoring

mcp-pvp provides comprehensive observability for production deployments:

- **Structured Logging**: Built on [structlog](https://www.structlog.org/) with JSON output
- **Audit Trail**: Complete audit trail of all PII operations (never logs raw values)
- **Error Tracking**: Optional [Sentry](https://sentry.io/) integration with PII protection
- **Metrics**: Prometheus-compatible metrics for requests, latency, and disclosures
- **Health Checks**: Ready-to-use health and readiness endpoints

See [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) for the complete guide and [examples/observability/](examples/observability/) for production configurations.

---

## Roadmap

### v0.2 ✅ (Current Release - Production Ready)

* ✅ PVP core: tokenize/resolve/deliver
* ✅ TTL store with session management
* ✅ Policy allow-lists + limits
* ✅ HMAC capabilities for sink-bound tokens
* ✅ MCP server binding with ToolExecutor
* ✅ Golden example: "safe email sender"
* ✅ Comprehensive observability (logging, metrics, Sentry)
* ✅ Production packaging (CHANGELOG, versioning, release workflow)
* ✅ Security scanning (Bandit integration)

### v0.3+ (Future)

* encrypted local persistence (sqlite)
* expanded detectors (IBAN, secrets, configurable patterns)
* richer audit queries and compliance reporting
* optional proxy mode (secure existing agents without refactor)
* enhanced policy primitives (time-based, context-aware)

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