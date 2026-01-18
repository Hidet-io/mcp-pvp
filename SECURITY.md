# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

To report a security vulnerability, please email: **security@hidet.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and work with you to understand and address the issue.

## Security Best Practices

### For Users

1. **Localhost only:** Keep HTTP binding on 127.0.0.1 (default). Do not expose to public networks.

2. **Shared secrets:** If using shared_secret auth, generate strong secrets:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **Policy review:** Review your policy configuration. Default-deny is enforced, but overly permissive rules weaken security.

4. **Tool trust:** Only use trusted MCP tools. PVP cannot prevent malicious tools from exfiltrating data.

5. **Update regularly:** Apply security updates promptly.

### For Developers

1. **Never log raw PII:** Use structured logging with correlation IDs only.

2. **Use deliver mode:** Prefer `pvp.deliver` over `pvp.resolve` to minimize PII exposure.

3. **Validate capabilities:** Always provide valid capabilities for disclosure.

4. **Respect policies:** Design workflows that work with default-deny policies.

5. **Session cleanup:** Close vault sessions when workflows complete.

## Known Limitations (v0.1)

- **In-memory storage:** Sessions are not persisted. Restart clears all data.
- **No encryption at rest:** PII stored in memory only (mitigated by localhost-only operation).
- **Detector accuracy:** PII detection uses regex or Presidio; false positives/negatives possible.
- **No rate limiting:** No per-client rate limiting beyond per-step disclosure limits.

## Security Features

- ✅ Default-deny policy enforcement
- ✅ HMAC-signed capabilities
- ✅ Time-bounded sessions and capabilities
- ✅ Audit logging (no raw PII)
- ✅ Localhost binding by default
- ✅ Anti-replay protection (optional)
- ✅ Constant-time signature verification

## Compliance Considerations

PVP helps reduce PII exposure but does not guarantee regulatory compliance. Consult legal/compliance teams for:

- GDPR
- CCPA
- HIPAA
- PCI-DSS
- Industry-specific requirements

## Future Security Roadmap

- [ ] Encrypted persistence (sqlite)
- [ ] Hardware security module (HSM) integration
- [ ] Audit log signing for immutability
- [ ] IP allow-lists
- [ ] Client authentication (mTLS)

---

For questions: security@hidet.io
