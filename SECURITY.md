# Security Policy

## Supported Versions

We actively support the latest major version of this package.

| Version | Supported |
|--------|-----------|
| 1.x    | ✅ Yes    |
| < 1.0  | ❌ No     |

Security fixes will be released as patch versions where possible.

---

## Reporting a Vulnerability

If you discover a security vulnerability in this package, **please do not open a public issue**.

Instead, report it responsibly by emailing:

**security@adgators.com**

Please include:
- A description of the issue
- Steps to reproduce (if possible)
- Any relevant code snippets or proofs of concept

You may encrypt your message if you prefer.

---

## Disclosure Process

After receiving a report, we will:

1. Acknowledge receipt within **72 hours**
2. Investigate and validate the issue
3. Prepare a fix and release a patched version
4. Publicly disclose the issue once a fix is available (if appropriate)

---

## Security Scope

This package is responsible for:
- Webhook signature format validation
- HMAC verification
- Replay attack mitigation

It is **not** responsible for:
- Transport security (HTTPS)
- Secret storage
- Server configuration
- Application-level authorization

Please ensure your environment follows security best practices.
