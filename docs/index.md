# mcp-pvp Documentation

`mcp-pvp` is a Privacy Vault Protocol that keeps sensitive data out of the LLM, agents, and telemetry while still powering real-world automations.

Use this site to explore the project architecture, operational guidance, and the auto-generated API docs that describe the core vault, policy, and request/response models exposed to your code.

## Highlights

- **Tokenization-first workflows** that replace text or JSON PII with typed references before sending plans to an LLM.
- **Deliver mode** that runs tools locally, injects PII securely, and returns result tokens for downstream visibility.
- **Policy enforcement, capabilities, and auditing** designed for security-conscious MCP deployments.

## Jump to...

- [Getting Started](getting-started.md) for installation tips, running the HTTP server, and a sample flow.
- [Vault Hardening Features](VAULT_HARDENING.md) for comprehensive documentation on session integrity, result tokenization, scanner performance, recursive scrubbing, and audit coherence.
- [Observability](OBSERVABILITY.md), [Capability Security](CAPABILITY_SECURITY.md), and [Threat Model](THREAT_MODEL.md) to understand how the vault protects data.
- [API Reference](api.md) powered by `mkdocstrings` so you can read accurate docstrings and signatures directly from the source.

## Local preview

Install the docs extras via `uv pip install -e "./[docs]"` (or include them in your `.[dev]` environment), then:

```bash
make docs           # live preview with MkDocs Material
make docs-build     # create the static `site/` tree
```

When the preview looks good, press the GitHub Pages button or run `make docs-deploy` to push the site to `gh-pages`.
