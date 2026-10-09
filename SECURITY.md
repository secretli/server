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
- Nothing of a secret is kept once it is deleted or expires, but its public id until the expiry (below). An opened one-time secret keeps only its encrypted object, the object's size and its expiry, for the download that opened it, and goes once that download ends; no token hash, so no link can tell it from a secret that never existed

### Reserved links

Whoever holds a link can derive everything a secret under it needs: its public id, its tokens and its keys. Someone who intercepted a link could therefore open a one-time secret and at once upload their own content under the same link, and the intended recipient would read that instead, with nothing to show the interception. A password does not stop this, since they would simply leave it out. So a public id stays taken until the expiry of the secret that took it, whether that secret is still there, was opened, or was deleted by its owner: an upload under it is refused like one under any id in use. The server keeps nothing for this but the id and the expiry, not whether the secret was opened or deleted, and the cleanup frees the id once the expiry has passed. An upload that was abandoned frees its id at once, since it never became a secret.

## Supported Versions

Only the latest image from `main` is supported with security updates.
