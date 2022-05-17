PGSERVICE ?= "secretli-local"

generate:
	sqlc -f db/sqlc.yaml -x generate


test: generate
	go test ./...


run: generate
	go run .


precommit:
	pre-commit run -a


migrate:
	PGSERVICE=$(PGSERVICE) tern migrate -m db/migrations

build-image-local:
	docker build -t secretli-local:latest .
