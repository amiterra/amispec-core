# syntax=docker/dockerfile:1.7
# AmiSpec validator / toolchain — context is this directory (amispec-core).
#
#   make docker-build     # runtime image (distroless)
#   make docker-test      # unit + conformance tests
#   make docker-shell     # build stage with cargo cache mounts
#
# Rebuild speed: BuildKit cache mounts for cargo registry/git and ./target.
# Dependency crates are prefetched in the `deps` stage and only re-fetched when
# Cargo.lock or crate manifests change.

ARG RUST_VERSION=1.85
ARG DEBIAN_VERSION=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS deps
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates/amispec-schema/Cargo.toml crates/amispec-schema/
COPY crates/amispec-validate/Cargo.toml crates/amispec-validate/
COPY crates/amispec-compile/Cargo.toml crates/amispec-compile/
COPY crates/amispec-cli/Cargo.toml crates/amispec-cli/
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    mkdir -p crates/amispec-schema/src crates/amispec-validate/src \
      crates/amispec-compile/src crates/amispec-cli/src \
    && : > crates/amispec-schema/src/lib.rs \
    && : > crates/amispec-validate/src/lib.rs \
    && : > crates/amispec-compile/src/lib.rs \
    && echo 'fn main() {}' > crates/amispec-cli/src/main.rs \
    && cargo fetch --locked

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ENV CARGO_TERM_COLOR=always
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --workspace --release --locked \
    && mkdir -p /out \
    && cp target/release/amispec /out/amispec \
    && strip /out/amispec || true

FROM rust:${RUST_VERSION}-slim-${DEBIAN_VERSION} AS test
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Conformance fixtures (synced by `make fixtures` from ../amispec/tests)
COPY tests/standard /amispec/tests
ENV CARGO_TERM_COLOR=always \
    AMISPEC_TEST_ROOT=/amispec/tests

# Layer: compile test binaries (cached until crates/**, Cargo.lock or fixtures change).
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --workspace --tests --locked

# Layer: execute tests every build. TEST_RUN_ID busts only this layer; compile
# work above stays cached, so re-runs are incremental and skip apt/dep setup.
ARG TEST_RUN_ID=dev
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    bash -euo pipefail -c '\
      echo "test-run-id=${TEST_RUN_ID}"; \
      cargo test --workspace --locked -- --nocapture 2>&1 | tee /tmp/cargo-test.log; \
      echo "=============================================="; \
      echo "amispec-core docker-test summary"; \
      echo "=============================================="; \
      grep -E "^test result:" /tmp/cargo-test.log || true; \
      if grep -E "FAILED|error\\[" /tmp/cargo-test.log >/dev/null; then \
        echo "RESULT: FAIL"; exit 1; \
      fi; \
      echo "RESULT: PASS"'
# Re-run tests on `docker run` (image entry for CI convenience)
CMD ["cargo", "test", "--workspace", "--locked"]

# Runtime: distroless cc (glibc) — matches the glibc-linked release binary.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=build /out/amispec /usr/local/bin/amispec
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/amispec"]

# ---------------------------------------------------------------------------
# musl — static binary → `FROM scratch` (~3–5 MB final image)
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-alpine AS build-musl
WORKDIR /src
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
ENV CARGO_TERM_COLOR=always
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --workspace --release --locked \
    && mkdir -p /out \
    && cp target/release/amispec /out/amispec \
    && strip /out/amispec || true

FROM scratch AS runtime-musl
COPY --from=build-musl /out/amispec /amispec
USER 65532:65532
ENTRYPOINT ["/amispec"]
