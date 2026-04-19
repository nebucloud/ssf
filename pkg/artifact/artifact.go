// Package artifact defines the uniform interface SSF operates on.
//
// Per SSF-ARCH-overview §4, every supply-chain operation in SSF (sign, verify,
// attest, sbom, log, policy) takes an [Artifact] as input. Concrete artifact
// types (binary, oci, crate, npm, derivation, blob) live in sibling files in
// this package and ship in later phases of NEB-PLAN-phasing 2.4 — the
// interface here is the only Phase 2.4a deliverable from this package.
//
// The interface is intentionally minimal: four pure-getter methods. SSF
// operations are stateless transformations against an artifact reference;
// nothing about the interface assumes mutable state, so implementations are
// free to be value types and concurrency-friendly by construction.
package artifact

// Type identifies which concrete implementation an Artifact uses.
//
// Stringly-typed (rather than a Go enum integer) so it round-trips cleanly
// through ssf.yaml, the kiln pipeline manifest, and the policy CUE schema —
// all three serialize the type as a lowercase identifier.
type Type string

// Recognized artifact types. New types must register both here and in
// SSF-SPEC-artifact-types so the spec, the policy schema, and the runtime
// stay synchronized.
const (
	TypeOCI        Type = "oci"
	TypeBinary     Type = "binary"
	TypeCrate      Type = "crate"
	TypeNPM        Type = "npm"
	TypeDerivation Type = "derivation"
	TypeBlob       Type = "blob"
)

// AllTypes is the canonical set of recognized [Type] values, ordered for
// stable iteration (used by `ssf init --type ...` validation and by the
// policy schema's enum constraint).
var AllTypes = []Type{
	TypeOCI,
	TypeBinary,
	TypeCrate,
	TypeNPM,
	TypeDerivation,
	TypeBlob,
}

// IsValid reports whether t is one of the recognized artifact types.
func (t Type) IsValid() bool {
	for _, known := range AllTypes {
		if t == known {
			return true
		}
	}
	return false
}

// Artifact is the uniform handle every SSF operation accepts.
//
// Implementations are value types or small structs; the interface intentionally
// exposes no mutation, so an [Artifact] can be passed by value across goroutine
// boundaries without synchronization.
//
// Concrete implementations live in sibling files in this package:
//   - oci.go:        registry-hosted container images
//   - binary.go:     standalone executables
//   - crate.go:      Rust .crate tarballs
//   - npm.go:        npm tarballs
//   - derivation.go: World Builder content-addressed outputs
//   - blob.go:       generic catch-all
//
// All except the interface itself land in Phase 2.4b+ — see NEB-PLAN-phasing.
type Artifact interface {
	// Type returns the artifact's type identifier (one of the constants
	// above). Used for type-specific dispatch in the pipeline runner and
	// for the policy schema's `type` field.
	Type() Type

	// Digest returns the artifact's content digest as a fully-qualified
	// hash string ("sha256:<64 hex>" or "blake3:<64 hex>"). The algorithm
	// is type-dependent — OCI uses sha256 (registry manifest digest),
	// derivations use blake3 (kiln content-addressed store), everything
	// else uses sha256 of the raw content.
	Digest() string

	// Reference returns the canonical locator for the artifact. Format
	// varies by type: "registry/name:tag" for OCI, a filesystem path or
	// URL for binary/blob, "name@version" for crate/npm, a store path
	// for derivation. See SSF-SPEC-artifact-types for the per-type spec.
	Reference() string

	// Metadata returns artifact-specific key-value pairs that policy
	// evaluation can reference. Conventional keys are documented per type
	// in SSF-SPEC-artifact-types — for example, OCI exposes "registry",
	// "namespace", "name", "tag", "manifest_type"; binary exposes
	// "filename", "size_bytes", "target_arch", "target_os",
	// "debug_symbols". Keys absent from the convention are still allowed
	// — policies that reference them simply fail to unify on artifacts
	// that omit them.
	Metadata() map[string]string
}
