# Changelog

All notable changes to mcp-pvp will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-15

### Added
- ToolExecutor interface for pluggable tool execution in deliver mode
- DummyExecutor reference implementation (returns stub responses)
- MCP_ToolExecutor for real MCP SDK integration
- Comprehensive security documentation in `docs/CAPABILITY_SECURITY.md`
- Sink-bound capabilities preventing cross-tool/sink reuse attacks
- 5 new tests for ToolExecutor integration (59 total tests)
- Initial alpha release
- Core vault operations: tokenize, resolve, deliver
- PII detection with Presidio and regex fallback
- Policy-based access control with sink policies
- HMAC-based capability tokens
- Audit logging with structured events
- Session management and cleanup
- Multiple token formats (TEXT, JSON)
- HTTP binding with FastAPI
- MCP binding (stub)
- 54 tests with 77% coverage


### Core Features
- **Tokenization**: Replace PII with tokens before LLM sees data
- **Resolution**: Translate tokens back to PII for approved sinks
- **Delivery**: Inject PII into tool calls and execute (stub in 0.1.0)
- **Policy**: Default-deny for LLM/ENGINE sinks, configurable allow rules
- **Capabilities**: HMAC tokens proving policy approval
- **Audit**: Comprehensive event logging (tokenize, resolve, deliver, policy denials)

### Security Model v0.1
- Policy-first enforcement (check before disclosure)
- Capability-based access (HMAC-signed tokens)
- Session isolation
- Per-session disclosure limits (100KB, 1000 values)
- Default deny for LLM and ENGINE sinks
- Regex-based PII detection (EMAIL, PHONE, IPV4, CC, API_KEY)

### Known Limitations (0.1.0)
- Tool execution stubbed (returns mock responses)
- Wildcard LOCAL capabilities allow reuse (fixed in 0.2.0)
- No async support
- In-memory storage only (no persistence)
- Presidio detector optional (falls back to regex)

---

## Version Compatibility

### Python Support
- **3.11+**: Required
- **3.12**: Fully tested
- **3.10**: Not supported (uses modern type hints)

### MCP SDK Compatibility
- **1.25.0+**: Required
- Tested with MCP SDK 1.25.x and 1.26.x

### Optional Dependencies
See [Installation](#installation) for package extras.

---

## Semantic Versioning Guide

mcp-pvp follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (x.0.0): Breaking API changes, incompatible upgrades
  - Example: Capability format changes, policy model changes
- **MINOR** (0.x.0): New features, backwards-compatible
  - Example: New detector types, new policy rule types
- **PATCH** (0.0.x): Bug fixes, security patches
  - Example: Fix regex patterns, fix HMAC verification

### Pre-1.0 Stability
While in 0.x versions:
- MINOR bumps MAY include breaking changes (documented in CHANGELOG)
- Security fixes may require breaking changes
- API is stabilizing but not guaranteed

### Upgrade Path
- Always read CHANGELOG before upgrading
- Test in staging environment first
- Check for BREAKING tags in release notes

---

## Deprecation Policy

Starting with v1.0:
- Deprecated features marked with `@deprecated` decorator
- Maintained for at least 2 MINOR versions
- Documented in CHANGELOG with migration guide
- Warnings logged when deprecated features used

---

## Release Process

1. Update version in `pyproject.toml` and `src/mcp_pvp/__init__.py`
2. Update CHANGELOG.md with release date
3. Create git tag: `git tag -a v0.x.x -m "Release v0.x.x"`
4. Push tag: `git push origin v0.x.x`
5. GitHub Actions builds and publishes to PyPI

---

## Security Releases

Security vulnerabilities are disclosed in CHANGELOG with:
- CVE identifier (if assigned)
- Severity rating (Critical, High, Medium, Low)
- Affected versions
- Fixed version
- Workarounds (if any)

Report security issues to: security@hidet.io
