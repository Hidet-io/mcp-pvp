# mcp-pvp — Privacy Vault Protocol for MCP

**Tokenize sensitive data before the LLM sees it.**  
`mcp-pvp` is a lightweight security/runtime layer for MCP-based agents and workflows that prevents accidental leakage of PII and secrets by design.

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

> This is **not** a vulnerability scanner/fuzzer for MCP servers.  
> It's a **privacy vault + policy enforcement runtime** for sensitive data in MCP workflows.

---

## Installation

### Using uv (recommended)

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/Hidet-io/mcp-pvp.git
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

# With Presidio detector (recommended for production)
pip install mcp-pvp[presidio]

# All extras
pip install mcp-pvp[all]
```

### Quick Start with Makefile

```bash
make help          # Show all available commands
make test          # Run tests
make lint          # Run linter
make format        # Format code
make check         # Run all checks (lint, format, typecheck, test)
make version       # Show current version
make bump-minor    # Bump version (e.g., 0.6.0 -> 0.7.0)
```

---

## Compatibility & Requirements

### Python Versions

- **Required**: Python 3.11+
- **Tested**: Python 3.11, 3.12

### MCP SDK

- **Required**: MCP SDK 1.26.0+

### Optional Dependencies (Extras)

```bash
pip install mcp-pvp[presidio]   # Microsoft Presidio for production-grade PII detection
pip install mcp-pvp[sentry]     # Sentry error tracking with PII protection
pip install mcp-pvp[all]        # Everything above + docs tooling
pip install mcp-pvp[dev]        # Development tools (pytest, ruff, mypy, etc.)
```

### Platform Support

- **Linux**: Fully supported ✅
- **macOS**: Fully supported ✅
- **Windows**: Supported ⚠️ (Presidio may require WSL for some languages)

---

## Quick Start

### Library Usage (standalone vault)

```python
from mcp_pvp import Vault, TokenizeRequest, DeliverRequest, ToolCall, Policy

vault = Vault(policy=Policy())

# Tokenize sensitive content
response = vault.tokenize(TokenizeRequest(content="Email me at alice@example.com"))
print(response.redacted)  # "Email me at [[PII:EMAIL:tkn_xyz]]"

# Deliver: inject PII locally into a tool call without returning raw values
deliver_resp = await vault.deliver(
    DeliverRequest(
        vault_session=response.vault_session,
        tool_call=ToolCall(name="send_email", args={"to": response.tokens[0].to_text()})
    )
)
# deliver_resp.tool_result is the tool's return value with PII re-tokenized
```

### MCP Server Integration (`FastPvpMCP`)

`FastPvpMCP` is a drop-in subclass of FastMCP that adds automatic PII protection to every tool call.  It uses MCP's native **lifespan** and **resource** primitives — no hidden arguments, no protocol changes.

```python
from mcp_pvp.bindings.mcp.server import FastPvpMCP
from mcp_pvp.models import Policy, PolicyAllow, PIIType, SinkPolicy
from mcp_pvp.vault import Vault

policy = Policy(
    sinks={
        "tool:send_email": SinkPolicy(
            allow=[PolicyAllow(type=PIIType.EMAIL, arg_paths=["to"])]
        )
    }
)

mcp = FastPvpMCP(name="my-server", vault=Vault(policy=policy))

@mcp.tool()
def send_email(to: str, subject: str, body: str) -> dict:
    """The 'to' argument arrives already resolved — no token handling needed."""
    return {"status": "sent", "to": to}

# Run as a standard FastMCP server
if __name__ == "__main__":
    mcp.run()
```

#### How it works end-to-end

```
Client connects
  └─ Server creates a vault session automatically (lifespan hook)

Client reads  pvp://session  resource
  └─ Receives vault_session_id

Client tokenizes PII:
  vault.tokenize(content="alice@example.com", vault_session=vault_session_id)
  └─ Returns token: [[PII:EMAIL:tkn_abc123]]

Client calls tool:
  session.call_tool("send_email", {"to": "[[PII:EMAIL:tkn_abc123]]", "subject": "Hi"})
  └─ No _vault_session argument — server reads it from the lifespan context

Server, transparently:
  1. Resolves token → "alice@example.com" (policy-checked)
  2. Invokes the real tool with resolved args
  3. Scans result for PII → re-tokenizes it
  4. Returns clean result to client

Client disconnects → vault session ends
```

#### Client-side usage with the MCP SDK

```python
import anyio
from mcp import ClientSession
from mcp.types import AnyUrl
from mcp_pvp.models import TokenizeRequest, TokenFormat

# ... set up memory streams or stdio transport ...

async with ClientSession(read_stream, write_stream) as session:
    await session.initialize()

    # Step 1: Discover the vault session for this connection
    resource = await session.read_resource(AnyUrl("pvp://session"))
    vault_session_id = resource.contents[0].text

    # Step 2: Tokenize PII before sending it
    resp = vault.tokenize(TokenizeRequest(
        content="alice@example.com",
        token_format=TokenFormat.TEXT,
        vault_session=vault_session_id,
    ))
    token = resp.tokens[0].to_text()  # "[[PII:EMAIL:tkn_abc123]]"

    # Step 3: Call the tool — no special arguments needed
    result = await session.call_tool("send_email", {"to": token, "subject": "Hi"})
    # result.content[0].text contains the re-tokenized JSON response
```

---

## Core Concepts

### Tokens (references, not values)

**Text token** (LLM-safe, passes through prompts):
```
[[PII:EMAIL:tkn_a1b2c3]]
```

**JSON token** (preferred for structured tool args):
```json
{ "$pii_ref": "tkn_a1b2c3", "type": "EMAIL", "cap": "cap_..." }
```

### Vault sessions

Tokens are scoped to a short-lived **vault session** (`vs_...`) with a TTL.  
A token is only valid within its session.

In `FastPvpMCP`, one vault session is created per MCP connection and lives for the duration of that connection.

### Capabilities (caps)

Even if an LLM is tricked into requesting disclosure, the vault requires a signed **capability** authorizing exactly: which token, for which sink/tool, at which argument path, within which time window.

### Sinks + policies

Policies are enforced **inside the vault**, default-deny:

- allow specific PII types
- only for specific tools (sinks), identified as `"tool:<name>"`
- optionally restricted to argument paths (e.g. `to`, `email`)

### Deliver mode (standalone) vs. `FastPvpMCP` (server mode)

| Mode | When to use |
|---|---|
| `vault.deliver()` | Standalone Python workflows, custom executors, non-FastMCP servers |
| `FastPvpMCP` | FastMCP-based servers — wraps every registered tool transparently |

In `FastPvpMCP`, deliver-mode semantics (resolve → execute → re-tokenize) happen automatically inside `call_tool()` using the connection-scoped vault session from the lifespan context.

---

## Policy Example

```python
from mcp_pvp.models import Policy, PolicyAllow, PIIType, SinkPolicy, PolicyLimits

policy = Policy(
    sinks={
        "tool:send_email": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.EMAIL, arg_paths=["to", "cc", "bcc"]),
            ]
        ),
        "tool:crm_upsert_contact": SinkPolicy(
            allow=[
                PolicyAllow(type=PIIType.EMAIL, arg_paths=["email"]),
                PolicyAllow(type=PIIType.PHONE, arg_paths=["phone"]),
            ]
        ),
    },
    limits=PolicyLimits(
        max_disclosures_per_step=50,
        max_total_disclosed_bytes_per_step=8192,
    ),
)
```

---

## PII Types

| Type | Default mode | Notes |
|---|---|---|
| `EMAIL` | Tokenize | |
| `PHONE` | Tokenize | Sanity-checked |
| `IPV4` | Tokenize | |
| `CC` | Mask | Optional tokenize with Luhn |
| `API_KEY` | Mask | Optional tokenize |

Names/addresses are intentionally excluded from the regex detector (too error-prone). Use the Presidio extra for those.

---

## What's Included

### Core Features

- ✅ PII detection (regex built-in; Presidio optional)
- ✅ Tokenization with typed opaque refs, structured tokens, and session TTLs
- ✅ Policy enforcement (sink allow-lists + limits) with capability checks
- ✅ HMAC-signed capabilities paired with audit events (no raw values in logs)
- ✅ Deliver mode: injects PII locally, re-tokenizes tool results, returns `result_tokens`
- ✅ `FastPvpMCP`: drop-in FastMCP subclass with connection-scoped vault sessions
- ✅ `pvp://session` MCP resource — standard resource protocol for session discovery
- ✅ Observability (structlog, Prometheus metrics, optional Sentry)

### Vault Hardening Features

- ✅ **Session Integrity Validation** — prevents cross-session token theft
- ✅ **Result Tokenization in Same Session** — session consistency for result tokens
- ✅ **Scanner-Based TEXT Token Parser** — O(n) state machine, 10–100× faster than regex
- ✅ **Recursive Output Scrubbing** — PII detection in exceptions, nested dicts, custom types
- ✅ **Audit Coherence** — parent-child event tracking for full request/response traceability

**Test Coverage**: 239 tests, 83% code coverage

---

## Running as MCP Server

```bash
# Start with stdio transport (works with Claude Desktop, MCP Inspector, etc.)
mcp-pvp-mcp
```

### Integrating with Claude Desktop

Add to `claude_desktop_config.json`:

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

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector
# Connect using command: mcp-pvp-mcp
```

---

## Threat Model (What This Helps With)

- Prompt injection: "print the user's email"
- Accidental logging/telemetry leaks
- Token spoofing (LLM hallucinates `tkn_...`)
- Over-broad restoration ("give me the full mapping")
- Unsafe tool exfiltration (policy + deliver reduces exposure)

> No library can fully protect a compromised device.  
> `mcp-pvp` minimizes common leakage paths and enforces least-privilege disclosure.

---

## Feature Matrix

| Capability | **mcp-pvp** | **Presidio** | **LangChain PII** | **Guardrails** | **HashiCorp Vault MCP** |
|---|---|---|---|---|---|
| High-quality PII detection | ✅ (Presidio optional) | ✅ | ✅ | ✅ | ❌ |
| Redaction / anonymization | ✅ | ✅ | ✅ | ✅ | ❌ |
| Local vault session (raw PII stays local) | ✅ | ❌ | ⚠️ | ❌ | ✅ (secrets, not PII) |
| Typed opaque tokens in prompts/plans | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ |
| Capability-based selective disclosure | ✅ | ❌ | ❌ | ❌ | ✅ (secrets API) |
| Per-tool / per-arg-path policy enforcement | ✅ | ❌ | ⚠️ | ✅ | ✅ |
| **Deliver mode** (PII injected locally, never returned to agent) | ✅ | ❌ | ❌ | ❌ | ❌ |
| MCP-native integration (lifespan, resources) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Audit trail (no raw values in logs) | ✅ | ⚠️ | ⚠️ | ✅ | ✅ |

---

## Observability & Monitoring

- **Structured Logging**: built on [structlog](https://www.structlog.org/) with JSON output
- **Audit Trail**: complete trail of all PII operations — raw values never logged
- **Metrics**: Prometheus-compatible metrics for requests, latency, and disclosures
- **Error Tracking**: optional [Sentry](https://sentry.io/) integration with PII scrubbing
- **Health Checks**: ready-to-use health and readiness endpoints

See [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) for the full guide and [examples/observability/](examples/observability/) for production configurations.

---

## Roadmap

### v0.6 ✅ (Current)

- ✅ PVP core: tokenize / resolve / deliver
- ✅ TTL store with session management
- ✅ Policy allow-lists + limits
- ✅ HMAC capabilities for sink-bound tokens
- ✅ `FastPvpMCP` — FastMCP subclass with transparent PII protection
- ✅ Connection-scoped vault sessions via MCP lifespan
- ✅ `pvp://session` MCP resource for standard session discovery
- ✅ Recursive result scrubbing (dicts, lists, exceptions, Pydantic models)
- ✅ Vault hardening: session integrity, audit coherence, scanner-based parser
- ✅ Comprehensive observability (logging, metrics, Sentry)

### Future

- Encrypted local persistence (SQLite)
- Expanded detectors (IBAN, secrets, configurable patterns)
- Richer audit queries and compliance reporting
- Optional proxy mode (protect existing agents without refactoring)
- Enhanced policy primitives (time-based, context-aware)

---

## Documentation

Full API and architecture docs are generated with MkDocs (Material theme + mkdocstrings).

```bash
make docs          # Preview locally
make docs-build    # Build static site
make docs-deploy   # Publish to GitHub Pages (requires GH_TOKEN)
```

Install docs dependencies: `uv pip install -e ".[docs]"`

---

## Contributing

We welcome:

- Detector modules (high precision, low false positives)
- Policy primitives and safe defaults
- Examples (email, CRM, ticketing, file access)
- Interoperability tests with MCP clients/servers
- Threat model improvements

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache-2.0
