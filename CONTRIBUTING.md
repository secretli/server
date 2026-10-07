# Contributing to the Secretli server

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

Prerequisites: Go 1.27+ and Docker.

```bash
git clone https://github.com/secretli/server.git
cd server

# Start Postgres and SeaweedFS
docker compose -f docker/docker-compose.yml up -d

# Configure environment
cp .env.example .env

# Run the server with auto-reload; migrations run at startup
make dev
```

## Running Tests

```bash
make test          # Full suite (needs Docker for the Postgres and S3 integration tests)
make test-short    # Fast unit tests only
make api-test      # The API over HTTP against a running server with raised rate limits
make lint          # golangci-lint
make vuln          # govulncheck
```

CI also runs the whole of Secretli with your change, from [secretli/e2e](https://github.com/secretli/e2e): the web app and both clients against this server.

## Submitting Changes

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add or update tests as needed
4. Ensure `make lint` and `make test` pass
5. Open a pull request against `main`

Keep pull requests focused: one feature or fix per PR. Changes to the encrypted format belong in [secretli/format](https://github.com/secretli/format), not here.

## Reporting Issues

Use [GitHub Issues](https://github.com/secretli/server/issues) for bugs and feature requests. For security vulnerabilities, see [SECURITY.md](SECURITY.md).
