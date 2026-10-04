.PHONY: all vet lint lint-sh test test-setup test-integration cover tidy image image-verify build-daemon licenses social-preview

# The reference sandbox image. See image/README.md for the contract it satisfies.
IMAGE ?= openblox-sandbox:dev

all: vet lint test

vet:
	go vet ./...

lint:
	golangci-lint run

# Every shell script we ship or run in CI.
lint-sh:
	shellcheck -x -s sh www/install.sh www/setup.sh .github/scripts/setup-unit.sh .github/scripts/setup-e2e.sh

test:
	CGO_ENABLED=1 go test -race -cover ./...

# Unit tests for www/setup.sh. They need no root.
test-setup:
	sh .github/scripts/setup-unit.sh

# Requires a gVisor-capable Docker host. See CONTRIBUTING.md.
test-integration:
	CGO_ENABLED=1 go test -race -tags integration ./...

cover:
	go test -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

tidy:
	go mod tidy

build-daemon:
	CGO_ENABLED=0 go build -trimpath -o bin/openbloxd ./cmd/openbloxd

# The licence bundle the release attaches to the openbloxd binaries. Generated,
# never committed — see the script for why.
licenses:
	.github/scripts/third-party-licenses.sh

# The social card. .github/assets/social-preview.svg is the source; this renders
# it to the two PNGs that actually ship — one uploaded in repository settings,
# one served as og:image from openblox.sh. Both are committed, because neither
# consumer can build them: GitHub takes an upload, and www/ has no build step.
social-preview:
	inkscape .github/assets/social-preview.svg \
	  --export-type=png --export-width=1280 --export-height=640 \
	  --export-filename=.github/assets/social-preview.png
	cp .github/assets/social-preview.png www/assets/social-preview.png

image:
	docker build -t $(IMAGE) image/

# The same assertions the publish workflow runs against the pushed manifest.
image-verify:
	docker run --rm --entrypoint /bin/sh $(IMAGE) -c \
	  'command -v bash && command -v python3 && command -v nc && [ "$$(id -u)" -ne 0 ]'
