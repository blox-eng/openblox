.PHONY: all vet lint test test-integration cover tidy image image-verify

# The reference sandbox image. See image/README.md for the contract it satisfies.
IMAGE ?= openblox-sandbox:dev

all: vet lint test

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	CGO_ENABLED=1 go test -race -cover ./...

# Requires a gVisor-capable Docker host. See CONTRIBUTING.md.
test-integration:
	CGO_ENABLED=1 go test -race -tags integration ./...

cover:
	go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

tidy:
	go mod tidy

image:
	docker build -t $(IMAGE) image/

# The same assertions the publish workflow runs against the pushed manifest.
image-verify:
	docker run --rm --entrypoint /bin/sh $(IMAGE) -c \
	  'command -v bash && command -v python3 && command -v nc && [ "$$(id -u)" -ne 0 ]'
