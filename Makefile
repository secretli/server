PGSERVICE ?= "secretli-local"

generate:
	go generate ./ent

test: generate
	go test ./...

run: generate
	go run .

precommit:
	pre-commit run -a

build-image-local:
	docker build -t secretli-local:latest .
