.PHONY: all vet lint test test-integration cover tidy

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
