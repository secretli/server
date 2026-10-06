# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Secretli, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email **patrick@pscheid.dev** with:

- A description of the vulnerability
- Steps to reproduce the issue
- Any potential impact you've identified

You should receive a response within 48 hours. If the issue is confirmed, a fix will be developed and released as soon as possible.

## Security Model

Secretli uses a zero-knowledge architecture:

- All encryption and decryption happens in the clients, the web app and the command-line client, following the format in [secretli/format](https://github.com/secretli/format)
- This server only stores opaque, encrypted blobs and never has access to plaintext data or encryption keys; CI checks that the format library is not among its dependencies
- Encryption keys are transported in URL fragments (`#`), which are never sent to the server
- Metadata, blob, and deletion bearer tokens are stored as SHA-256 hashes, not raw tokens
- Tombstones of gone secrets hold no content and no key material, only the token hashes that guard them, the outcome and its times

## Supported Versions

Only the latest image from `main` is supported with security updates.
