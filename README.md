# ssf — NebuCloud Secure Software Factory

Go CLI that applies supply-chain security operations to any artifact: container images, Rust crates, npm packages, World Builder derivations, standalone binaries, or arbitrary blobs. The same pipeline signs, attests, generates SBOMs, logs to transparency records, and evaluates CUE policies across every artifact type.

ssf does not run builds. [kiln](https://github.com/nebucloud/kiln) runs builds. ssf secures the output.

```
source → kiln (hermetic build) → artifact → ssf (sign/attest/sbom/verify/policy) → published
```

See [SSF-ARCH-overview](https://github.com/nebucloud/docs/blob/main/SSF-ARCH-overview.md) for the architecture, [SSF-SPEC-ssf-yaml](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-ssf-yaml.md) for the pipeline definition spec, [SSF-SPEC-policies](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-policies.md) for the CUE policy library, and [NEB-PLAN-phasing §2.4](https://github.com/nebucloud/docs/blob/main/NEB-PLAN-phasing.md) for delivery sequencing.

## Status

Phase 2.4a — scaffold complete. Every subcommand is registered and shows in `ssf --help`; handlers return a "not yet implemented" error pointing at the phase that lands them.

| Phase | Scope | Status |
|-------|-------|--------|
| 2.4a | Go module, cobra CLI tree, `Artifact` interface | ✅ this commit |
| 2.4b | First artifact type (binary), `ssf sign` / `ssf verify` | pending |
| 2.4c | `ssf.yaml` parser → kiln JSON manifest emitter, `ssf run`, `ssf init`, attest/sbom/log | pending |
| 2.4d | CUE policy library, `ssf policy check`, structured report | pending |

## Build

```sh
go build ./cmd/ssf
./ssf --help
```

## Repository layout

```
ssf/
├── cmd/
│   └── ssf/
│       └── main.go              # binary entrypoint
├── internal/
│   └── cli/
│       ├── root.go              # cobra root + subcommand registration
│       ├── stub.go              # shared "not yet implemented" handler
│       ├── sign.go
│       ├── verify.go
│       ├── attest.go
│       ├── sbom.go
│       ├── log.go
│       ├── policy.go            # `policy {check,list,validate,explain,schema}`
│       ├── run.go
│       └── init.go
├── pkg/
│   └── artifact/
│       ├── artifact.go          # public Artifact interface + Type constants
│       └── artifact_test.go
├── go.mod
└── go.sum
```

`internal/cli` is implementation detail of the binary. `pkg/artifact` is the only public surface for now — external Go consumers (the future SSF MCP server in Conductor, third-party policy tooling, etc.) import it directly.

## License

Dual-licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
