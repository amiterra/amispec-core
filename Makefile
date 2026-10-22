# amispec-core — build, test, docker
#
# Layout:
#   make test          # cargo test (unit + conformance)
#   make build         # release build
#   make docker-build  # runtime image (distroless)
#   make docker-test   # tests inside Docker (needs `make fixtures`)
#   make fixtures      # sync ../amispec/tests → tests/standard (for Docker)

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:

CARGO     ?= cargo
IMAGE     ?= amispec-core
RUST_VER  ?= 1.85
FIXTURES  := tests/standard
STANDARD  ?= ../amispec

.PHONY: all build test test-fast fmt fmt-check clippy clean \
        fixtures docker-build docker-build-minimal docker-test docker-shell release

all: build

## Build (debug) — incremental; deps rebuilt only if lockfile changes
build:
	$(CARGO) build --workspace

## Build (release, optimized)
release:
	$(CARGO) build --workspace --release

## Full test suite (unit + doctests + conformance fixtures)
test:
	$(CARGO) test --workspace

## Fast feedback: library tests only
test-fast:
	$(CARGO) test -p amispec-validate -p amispec-schema -p amispec-compile --lib

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

clean:
	$(CARGO) clean
	rm -rf $(FIXTURES)

## Sync AmiSpec standard fixtures (required before docker-test)
fixtures:
	rm -rf $(FIXTURES)
	mkdir -p $(FIXTURES)
	cp -R $(STANDARD)/tests/valid $(FIXTURES)/valid
	cp -R $(STANDARD)/tests/invalid $(FIXTURES)/invalid
	@echo "fixtures → $(FIXTURES) (from $(STANDARD)/tests)"

## Runtime image (distroless glibc, ~35 MB)
docker-build: fixtures
	docker build \
		--build-arg RUST_VERSION=$(RUST_VER) \
		--target runtime \
		-t $(IMAGE):latest \
		.

## Minimal runtime image (static musl on scratch, ~5 MB)
docker-build-minimal: fixtures
	docker build \
		--build-arg RUST_VERSION=$(RUST_VER) \
		--target runtime-musl \
		-t $(IMAGE):minimal \
		.

## Tests inside Docker
## - apt / deps / `cargo build --tests` layers stay cached unless sources change
## - TEST_RUN_ID busts only the final `cargo test` layer (results always print)
docker-test: fixtures
	@echo "==> docker build --target test (cached compile + live cargo test)"
	docker build \
		--build-arg RUST_VERSION=$(RUST_VER) \
		--build-arg TEST_RUN_ID=$$(date +%s) \
		--target test \
		--progress=plain \
		-t $(IMAGE):test \
		.
	@echo "==> docker-test finished"

## Interactive build stage (shared cargo caches)
docker-shell: fixtures
	docker build \
		--build-arg RUST_VERSION=$(RUST_VER) \
		--target build \
		-t $(IMAGE):build \
		.
	docker run --rm -it \
		-v "$$(pwd)/crates:/src/crates:rw" \
		$(IMAGE):build \
		bash

## Validate standard fixtures with the local binary
validate-standard:
	$(CARGO) run -q -p amispec-cli -- validate $(STANDARD)/tests/valid
