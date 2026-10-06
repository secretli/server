.PHONY: dev build test test-short test-coverage e2e lint vuln clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/secretli/server/cmd.Version=$(VERSION)

# The server with auto-reload via Air (needs Postgres and SeaweedFS from docker/)
dev:
	air -c .air.toml

# The binary, at bin/secretli
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/secretli .

# Full test suite, including the Postgres and S3 integration tests (needs Docker)
test:
	go test -race -cover ./...

# Unit tests only, no containers
test-short:
	go test -short -cover ./...

test-coverage:
	go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# End-to-end against a running server, driven by the secretli command-line
# client. SECRETLI_SERVER and SECRETLI_CLI override the defaults.
e2e:
	./scripts/e2e.sh

lint:
	golangci-lint run ./...

# Known-vulnerability scan of Go dependencies
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean:
	rm -rf bin/ tmp/ coverage.out
