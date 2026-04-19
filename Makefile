GO ?= go
GOLANGCI_LINT ?= golangci-lint
GRYPE ?= grype
SYFT ?= syft

GRYPE_ARGS ?=
SYFT_ARGS ?=

BUILD_DIR ?= build
SBOM_DIR ?= $(BUILD_DIR)/sbom

-include Makefile.config

.PHONY: all build build-lib test test-race test-cover cover
.PHONY: vet fmt fmt-check lint grype sbom clean

all: build

build: build-lib

build-lib:
	$(GO) build ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-cover:
	$(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...

cover: test-cover
	$(GO) tool cover -func=coverage.out | tail -1

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt found unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

lint:
	$(GOLANGCI_LINT) run --config=.github/golangci.yml ./...

grype:
	$(GRYPE) -c .github/grype.yaml $(GRYPE_ARGS) dir:./

sbom:
	mkdir -p "$(SBOM_DIR)"
	$(SYFT) $(SYFT_ARGS) dir:./ -o cyclonedx-json="$(SBOM_DIR)/cabe-go.cdx.json"

clean:
	rm -f coverage.out
	rm -rf "$(BUILD_DIR)"
