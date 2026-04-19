# ssf — Claude orientation

NebuCloud Secure Software Factory. Go CLI that signs / attests / SBOMs / logs / policy-evaluates artifacts. Builds via kiln; this repo only secures the output.

Canonical specs:
- [SSF-ARCH-overview](https://github.com/nebucloud/docs/blob/main/SSF-ARCH-overview.md) — architecture, CLI surface, MCP tools
- [SSF-SPEC-ssf-yaml](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-ssf-yaml.md) — pipeline definition file
- [SSF-SPEC-policies](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-policies.md) — CUE policy library
- [SSF-SPEC-artifact-types](https://github.com/nebucloud/docs/blob/main/SSF-SPEC-artifact-types.md) — per-type behavior (digest computation, sign mechanism, where signatures live)
- [KLN-D-extraction-decisions §02](https://github.com/nebucloud/docs/blob/main/KLN-D-extraction-decisions.md) — kiln accepts JSON pipeline manifests, NOT `.lattice`. ssf emits JSON.
- [NEB-PLAN-phasing §2.4](https://github.com/nebucloud/docs/blob/main/NEB-PLAN-phasing.md) — delivery sequence

## Phasing

| Phase | Deliverable |
|-------|-------------|
| 2.4a (current) | Scaffold + cobra tree + `Artifact` interface. Every subcommand stubs; `ssf --help` lists the surface. |
| 2.4b | First artifact type: **binary** (not OCI per arch-doc — picked binary first so the test artifact has no registry-credential prerequisite; SSF can self-secure its own binary). `ssf sign` / `ssf verify` shelling to `cosign sign-blob` / `cosign verify-blob`. |
| 2.4c | `ssf.yaml` parser → kiln JSON pipeline manifest emitter → invoke `kiln run`. Adds `ssf attest`, `ssf sbom`, `ssf log`, `ssf init`. Tools (cosign, syft, cue, rekor-cli) must be on PATH for v1 (kiln-cli ships with `MockFetcher`; World Builder–provisioned tools are a future phase). |
| 2.4d | CUE policy library (base.cue, strict.cue), CUE evaluator, `ssf policy check` with structured pass/fail report. Phase 2.4 exit criterion satisfied. |

## Repo layout

```
cmd/ssf/main.go      — binary entrypoint, no logic
internal/cli/        — cobra command tree (one file per subcommand)
                       internal/ keeps it private; nobody outside this binary
                       imports it
pkg/artifact/        — public Artifact interface + Type constants. The only
                       package external consumers (SSF MCP server, third-party
                       policy tooling) should import.
```

`internal/cli/stub.go` exports `notImplemented(phase string)` — the shared run handler every Phase 2.4a stub uses. When you implement a real handler, delete the `RunE: notImplemented(...)` line and write the real `RunE`.

## Conventions

- **Comment Go like the Microsoft style**: doc comments on every exported identifier, summary first sentence, "Returns ..." / "Errors ..." subsections where they add value. Don't comment what well-named code already says.
- **No backwards-compat shims** until v1.0. Break the CLI surface freely as the spec evolves.
- **Tests** live next to the code (`*_test.go`). Table-driven where the surface is enumerable; integration tests against real cosign/kiln land in 2.4b+.
- **Errors propagate to main** which formats them as `ssf: <error>` to stderr and exits non-zero. Avoid `log.Fatal` outside main.

## Adding a new subcommand

1. Create `internal/cli/<name>.go` with a `new<Name>Command()` constructor returning `*cobra.Command`.
2. Wire it into `NewRootCommand()` in `internal/cli/root.go`.
3. Stub it with `RunE: notImplemented("2.4x")` until the real handler is ready.
4. Add table-driven validation tests in `<name>_test.go` once flags are non-trivial.

## Adding a new artifact type

1. Add the lowercase identifier as a `Type` constant in `pkg/artifact/artifact.go`.
2. Add it to `AllTypes`.
3. Add a row to `SSF-SPEC-artifact-types` so the spec stays in lockstep.
4. Implement the new type in `pkg/artifact/<name>.go` and add to the pipeline runner's type-dispatch.

## License

Dual MIT / Apache-2.0 (matching kiln's licensing).
