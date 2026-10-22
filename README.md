# amispec-core

Rust **library-first** implementation of the [AmiSpec](https://github.com/amiterra/amispec) standard:
configuration **validation** and **compilation** (plus lossless reverse
decompile) for k3s / FluxCD.

> **Product CLI.** The broad product CLI is **`ami`** (amiterra). This repository
> ships embeddable crates and a thin `amispec` binary for CI and standalone use.
> The validator is **not** embedded in the compiler at runtime — pipeline order is
> *validate → compile* (see [Consumption](#consume-from-another-cli)).

## Workspace

| Crate | Role |
| --- | --- |
| `amispec-schema` | Typed model + `AMISPEC_STANDARD_VERSION = 1.0.0` |
| `amispec-validate` | **Validator** — structural + semantic (+ optional `cue vet`) |
| `amispec-compile` | **Compiler** — 7-stage FluxCD tree + **decompile** (Provenance) |
| `amispec-cli` | Thin CLI: `validate` / `compile` / `decompile` / `version` |

Standard sources live in [AmiSpec](https://github.com/amiterra/amispec) (`docs/specification.adoc`,
`schemas/*.cue`, conformance fixtures).

## Validator

* Covers kind/apiVersion, metadata, parameters, topologyModes, workload,
  interfaces (endpoints, `clientContract`, provisioner), hardware/kernel,
  operations, topology clusters/nodes/CNI/components/bindings, CanvasLayout.
* Hand-written pattern matchers (no `regex`); `cue vet` only as optional layer.
* Error format: `error|warn [<rule-id>] <path>: <message>`.

```bash
amispec validate path/to/file.yaml
amispec --cue --schema-dir ../amispec/schemas validate file.yaml
```

## Compiler & decompile

```bash
# topology + passports → k3s/FluxCD tree (7 stages + Provenance)
amispec compile ../amispec/tests/valid/topology-minimal.yaml -o out/

# FluxCD tree (amispec.io/* labels) → topology.yaml (lossless)
amispec decompile out/ -o reconstructed.yaml
```

Stages: `flux-system`, `01-node-tuning`, `02-operators-and-networking`,
`03-stateful-clusters`, `04a-provisioners-day2`, `04b-app-migrations-expand`,
`05-applications`, `06-zero-trust-and-observability`, plus `clusters/_meta/`.

Provenance labels: `amispec.io/component-id`, `passport`, `zone`,
`injected-sidecars`, `binding-edge`, `user-spec-delta`, `cluster-id`, `stage`.

Round-trip: `decompile(compile(T))` preserves ids, passport pins
(`id@version-rev`), topology mode/replicas, resources, bindings, expose,
autoscaling. Synthetic objects (sidecars, hashed Jobs) are omitted.

## Build & test

Requires **Rust 1.85+** (edition 2024).

```bash
make build            # debug (incremental)
make release          # optimized
make test             # full suite (unit + integration + doctests)
make test-fast        # library unit tests only
make fmt clippy       # style / -D warnings
make validate-standard  # run validator on ../amispec/tests/valid
```

`make test` currently runs **51 tests** (validate 18 + compile 27 + schema 2 +
CLI 3 + doctests). Conformance fixtures come from `../amispec/tests`.

## Docker

BuildKit cache mounts keep dep setup cached; `TEST_RUN_ID` busts only the final
`cargo test` layer so results always print.

```bash
make fixtures              # sync ../amispec/tests → tests/standard
make docker-build          # distroless/cc (~35 MB)
make docker-build-minimal  # musl + scratch (~1.3 MB)
make docker-test           # cargo test in container (with summary)
make docker-shell          # interactive build stage
```

| Image | Base | Size |
| --- | --- | --- |
| `amispec-core:latest` | distroless/cc-debian12 | ~35 MB |
| `amispec-core:minimal` | `scratch` + static musl | ~1.3 MB |
| `amispec-core:test` | rust-slim | test only |

## Consume from another CLI

```toml
[dependencies]
amispec-schema   = { path = "../amispec-core/crates/amispec-schema" }
amispec-validate = { path = "../amispec-core/crates/amispec-validate" }
amispec-compile  = { path = "../amispec-core/crates/amispec-compile" }
```

```rust
let report = amispec_validate::validate_file(path, &opts);
if !report.is_ok() {
    for e in report.errors() {
        eprintln!("{}: {}", e.path, e.message);
    }
}
let topo = amispec_schema::parse_topology(&yaml)?;
let out = amispec_compile::compile(&topo, &PassportIndex::default(), &opts)?;
```

Pipeline recommendation: **validate first, then compile**. The compiler assumes a
well-formed `TopologyBlueprint`; it does not call the validator internally.

## Dependencies (minimal)

* `serde`, `serde_yaml`, `serde_json`, `thiserror`, `walkdir`
* CLI: `clap`, `anyhow`
* **No** `regex`, `indexmap`, `tokio`, async stack

## Language

English only (docs, comments, error strings), matching the AmiSpec specification.

## License

Apache-2.0.
