# ssf — NebuCloud Secure Software Factory

Go CLI that applies supply-chain security operations to any artifact: container images, Rust crates, npm packages, World Builder derivations, standalone binaries, or arbitrary blobs. The same pipeline signs, attests, generates SBOMs, logs to transparency records, and evaluates CUE policies across every artifact type.

ssf does not run builds. [kiln](https://github.com/nebucloud/kiln) runs builds. ssf secures the output.

```
source → kiln (hermetic build) → artifact → ssf (sign/attest/sbom/verify/policy) → published
```

See [SSF-ARCH-overview](https://github.com/nebucloud/docs/blob/main/SSF-ARCH-overview.md) for the architecture, [SSF-SPEC-ssf-yaml](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-ssf-yaml.md) for the pipeline definition spec, [SSF-SPEC-policies](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-policies.md) for the CUE policy library, and [NEB-PLAN-phasing §2.4](https://github.com/nebucloud/docs/blob/main/NEB-PLAN-phasing.md) for delivery sequencing.

## Status

Phases 2.4a–d complete for the binary path. **OCI** artifact type is wired for
`ssf sign` / `ssf verify` and kiln emit (`cosign sign` / `cosign verify`).

| Phase | Scope | Status |
|-------|-------|--------|
| 2.4a | Go module, cobra CLI tree, `Artifact` interface | ✅ |
| 2.4b | Binary artifact, `ssf sign` / `ssf verify` (sign-blob) | ✅ |
| 2.4c | `ssf.yaml` → kiln JSON, `ssf run` / `init` / attest / sbom / log | ✅ |
| 2.4d | CUE policy library, `ssf policy check`, structured report | ✅ |
| OCI | Registry images: digest resolve + `cosign sign` / `verify` | ✅ |

```sh
ssf sign --key file://cosign.key ghcr.io/org/image:v0.1.0
ssf verify --key file://cosign.pub ghcr.io/org/image:v0.1.0
ssf run --dry-run testdata/sample-oci.ssf.yaml
```

## Install

```sh
go install github.com/nebucloud/ssf/cmd/ssf@latest
```

Requires a Go toolchain on `PATH`. Cosign must be available for OCI sign/verify.

## Build

```sh
go build ./cmd/ssf
./ssf --help
```

## License

Dual-licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.
