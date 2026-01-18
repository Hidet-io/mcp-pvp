# Getting Started

## Install

The recommended path is to use `uv`, which bootstraps isolated environments quickly:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/Spidux-ai/mcp-pvp.git
cd mcp-pvp
uv venv
source .venv/bin/activate
uv pip install -e "[all]"
```

If you prefer `pip`, install the published package with the extras you need:

```bash
pip install mcp-pvp              # tokenization core
pip install mcp-pvp[presidio]    # high-accuracy detectors
pip install mcp-pvp[http]        # HTTP API server
pip install mcp-pvp[docs]        # MkDocs preview tools
```

## Run the services

* `make run-http` spins up the FastAPI + Uvicorn HTTP binding (`mcp_pvp.bindings.http.app`).
* `make run-mcp` launches the MCP stub server that exposes `pvp.tokenize`, `pvp.resolve`, `pvp.deliver` as MCP tools.
* `examples/safe_email_sender/` demonstrates a delivery-style workflow that uses the vault before reaching out to real email tooling.

## Deliver mode mindset

1. Tokenize sensitive strings with `Vault.tokenize()` or the HTTP `/tokenize` route.
2. Let the agent plan with tokens instead of raw values.
3. Run `Vault.deliver()` (or `pvp.deliver`) to inject the real values locally and execute the tool.
4. `DeliverResponse` now carries both the sanitized tool result and `result_tokens` describing every detected PII span so you can audit leaks.

## Next steps

- Read the [Protocol Specification](SPEC.md) for how tokens, policies, and sessions interact.
- Review [Capability Security](CAPABILITY_SECURITY.md) for advice on issuing sink-specific capabilities.
- Browse the [API Reference](api.md) to see the exact arguments you feed into `Vault`, `Policy`, and the request/response models.
