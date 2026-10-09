# Secretli server

The API behind [Secretli](https://secretli.app). It stores secrets that were encrypted before they arrived, hands them back to whoever proves they hold the link, and forgets them when they are opened or expire.

The server cannot read what it stores. Keys are derived and used only by the clients, the [web app](https://github.com/secretli/web) and the [command-line client](https://github.com/secretli/cli), which follow the format specified in [secretli/format](https://github.com/secretli/format). The link's secret travels in the URL fragment, which never reaches a server. What arrives here is ciphertext, an encrypted metadata envelope, and three tokens, of which only SHA-256 hashes are kept. CI checks that the format library, the code that could derive a key, is never among this server's dependencies.

## What it does

- **Uploads:** a secret arrives as a multipart upload session. Parts of up to 32 MiB are streamed into S3-compatible storage and assembled when the session completes, so no request ever carries the whole secret. The secret's lifetime counts from the completed upload. Its times are kept to the minute, with one minute added so that it never lives shorter than chosen, and none of them tells how long the upload took.
- **Retrieval:** the link's metadata token unlocks the encrypted metadata. Its blob token opens a 15-minute retrieval session that reads the bundle by byte range. Opening a one-time secret closes it: nobody can open it again, and only the download that opened it can still read it, until that session ends.
- **Owner status:** a link can tell whether a recipient has opened a reusable secret. Never when. Once a secret is deleted, expires or, being one-time, has been opened, nothing about it is told: its link gets the same 404 as one that never existed.
- **Deletion:** the owner link's deletion token removes a secret at once; its object leaves storage within a minute.
- **Short-code hand-off:** a relay through which two devices pass a link after a password-authenticated key exchange. The server only sees public key-exchange shares and ciphertext.
- **Cleanup:** a worker runs every minute. It forgets secrets past their expiry and opened one-time secrets whose download ended, abandons uploads that ran out of time, and is the only code that deletes from storage: every object is on file from before it is written until after it is deleted, so storage never holds one the database has forgotten.
- **Logs:** a request is logged by its route, not its path, so the logs don't say which secret was asked for.

### Endpoints

| Method and path | Purpose |
|---|---|
| `POST /api/v1/secrets/uploads` | start an upload session for a new secret |
| `PUT /api/v1/secrets/uploads/{session}/parts/{n}` | upload one part |
| `POST /api/v1/secrets/uploads/{session}/complete` | turn the parts into the secret |
| `DELETE /api/v1/secrets/uploads/{session}` | abandon an upload |
| `GET /api/v1/secrets/{id}/meta` | the encrypted metadata, and whether a recipient opened a reusable secret |
| `POST /api/v1/secrets/{id}/retrieval-session` | open the secret for reading |
| `GET /api/v1/secrets/{id}/blob` | read a byte range within a retrieval session |
| `DELETE /api/v1/secrets/{id}` | delete, with the owner's deletion token |
| `POST /api/v1/transfers`, `/claim`, `/{id}/answer`, `/{id}/delivery` | the short-code relay |
| `GET /api/v1/version` | the commit the server was built from |
| `GET /api/v1/health/live`, `/api/v1/health/ready` | liveness and readiness |
| `GET /metrics` | Prometheus metrics, optionally behind a bearer token |

The secret, upload and transfer endpoints are rate limited per client address; health, version and metrics are not.

## Running it

The server needs PostgreSQL and an S3-compatible object store. Migrations run at startup.

```bash
docker compose -f docker/docker-compose.yml --profile app up -d
```

starts the server on `http://localhost:8080` with PostgreSQL and SeaweedFS. Without `--profile app` you get only the two backing services, for running the server from source:

```bash
docker compose -f docker/docker-compose.yml up -d
cp .env.example .env
make dev
```

### Configuration

Environment variables; see [`.env.example`](.env.example).

| Variable | Description | Default |
|---|---|---|
| `SERVER_PORT` | HTTP port | `8080` |
| `DATABASE_URL` | PostgreSQL connection string | — |
| `S3_ENDPOINT` | URL of the S3-compatible API, with `http://` or `https://` | — |
| `S3_BUCKET` | bucket name, which must exist | — |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | S3 credentials | — |
| `S3_REGION` | region for request signing | `us-east-1` |
| `MAX_FILE_SIZE` | encrypted upload limit in bytes | `1073741824` (1 GiB) |
| `MAX_STORED_BYTES` | cap on what all secrets together may take up in storage; a new upload past it gets 503 with `Retry-After` (0: no cap) | `0` |
| `CLEANUP_INTERVAL` | how often the cleanup runs | `1m` |
| `ALLOWED_ORIGINS` | CORS origins, only needed when the web app is served from another origin | — |
| `METRICS_TOKEN` | bearer token required for `/metrics` | — |
| `TRUSTED_PROXIES` | IPs or CIDRs of reverse proxies whose `X-Forwarded-For` is trusted for rate limiting | — |
| `RATE_LIMIT_MULTIPLIER` | raises every rate limit by this whole factor, for test environments only | `1` |

Behind a reverse proxy, set `TRUSTED_PROXIES` to the proxy's address so rate limits key on the real client; otherwise forwarded headers are ignored.

Rate limits apply per client address, and an end-to-end suite sends far more requests from one address than a visitor would. Test environments set `RATE_LIMIT_MULTIPLIER` (for example to `100`) instead of waiting out the limits. It is read once at startup and never from a request, anything but a whole number of at least 1 stops the server from starting, and a server with raised limits logs a warning. Production leaves it unset.

## Development

```bash
make test        # everything, including the Postgres and S3 integration tests (needs Docker)
make test-short  # unit tests only
make api-test    # the API, over HTTP, against a running server; see below
make lint
make vuln
```

The API test (`apitest/`) checks a running server through its HTTP API alone, with no client and no format library: uploads in one and several parts, the upload rules, metadata, retrieval and byte ranges, one-time and reusable secrets, that a gone secret answers like one that never was, deletion, times kept to the minute, and the short-code relay. The server never decrypts anything, so random bytes stand in for ciphertext. It sends more requests than the rate limits allow from one address, so the server under test needs raised limits:

```bash
make build && RATE_LIMIT_MULTIPLIER=100 ./bin/secretli   # with DATABASE_URL and S3_* set
SECRETLI_SERVER=http://localhost:8080 make api-test
```

One test waits about six minutes for a secret to expire and runs only with `SECRETLI_SLOW_TESTS=1` set.

CI runs the API test against a fresh server at every change. It also runs the whole of Secretli with the change, from [secretli/e2e](https://github.com/secretli/e2e): the web app and both clients against this server behind a gateway like production's, with the newest command-line client and the oldest one the server still supports (v0.3.0). Nothing is published unless both pass.

Database queries are generated with [sqlc](https://sqlc.dev) from `internal/adapter/postgres/queries`; run `sqlc generate` after changing them or the migrations.

## Images

Every change on `main` that passes CI is published to the GitHub Container Registry:

```
ghcr.io/secretli/server:main
ghcr.io/secretli/server:sha-<commit>
ghcr.io/secretli/server:<YYYYMMDD-HHmmss>-<commit>
```

The images are built for `linux/amd64` and `linux/arm64` on distroless, carry an SBOM and SLSA provenance, and are signed with [cosign](https://github.com/sigstore/cosign), keyless:

```bash
cosign verify ghcr.io/secretli/server:main \
  --certificate-identity-regexp 'https://github.com/secretli/server/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

[MIT](LICENSE)
