// Package pipeline parses ssf.yaml and emits the kiln pipeline manifest that
// `ssf run` hands off to kiln.
//
// Per SSF-ARCH-overview §6 + SSF-SPEC-ssf-yaml §2, the user-authored
// ssf.yaml describes _what_ to do (sign, attest, sbom, log, policy) at the
// SSF level; this package translates that intent into _how_ to do it (a kiln
// JSON pipeline of bash targets) per KLN-D-02. The data flow is:
//
//	ssf.yaml  →  pipeline.Pipeline (this package)  →  kiln.Pipeline JSON  →  kiln run
//
// The schema types here mirror SSF-SPEC-ssf-yaml §3 one-to-one. Keep them in
// sync — adding a field requires both a struct change here and a §3 edit so
// the spec doesn't drift from the implementation.
package pipeline

import "github.com/nebucloud/ssf/pkg/artifact"

// SchemaVersion is the only ssf.yaml `version` value the parser accepts in
// Phase 2.4c. Version bumps land alongside breaking schema changes.
const SchemaVersion = "1"

// Pipeline is the full ssf.yaml document, in-memory. Field names use snake
// case via yaml tags so they match the spec's wire form, while Go-side names
// stay idiomatic (Pipeline.Steps, not Pipeline.Pipeline).
type Pipeline struct {
	Version  string            `yaml:"version"`
	Artifact ArtifactSpec      `yaml:"artifact"`
	Signing  SigningSpec       `yaml:"signing"`
	Tools    map[string]string `yaml:"tools,omitempty"`
	Steps    []Step            `yaml:"pipeline"`
	Policy   *PolicyDefaults   `yaml:"policy,omitempty"`
	Output   *OutputSpec       `yaml:"output,omitempty"`
}

// ArtifactSpec identifies the artifact the pipeline operates on. Reference is
// type-dependent (path for binary, repo URL for crate, etc. — see
// SSF-SPEC-artifact-types).
type ArtifactSpec struct {
	Type      artifact.Type     `yaml:"type"`
	Reference string            `yaml:"reference"`
	Digest    string            `yaml:"digest,omitempty"`
	Metadata  map[string]string `yaml:"metadata,omitempty"`
}

// SigningSpec carries the signing-key reference. Format follows the same
// surface the CLI's --key flag accepts — see internal/cli/cosign.go's
// translateKey for the recognized prefixes (cosign | file://path |
// vault://transit/<name> | fulcio | <KMS URI>).
type SigningSpec struct {
	Key string `yaml:"key"`
}

// Step is a single entry in the pipeline. The Step.Step field discriminates
// which other fields are valid — see StepSign/StepSBOM/etc constants and the
// per-kind field documentation.
type Step struct {
	Step       StepKind    `yaml:"step"`
	Format     string      `yaml:"format,omitempty"`     // sbom: spdx | cyclonedx
	Output     string      `yaml:"output,omitempty"`     // sbom: output file path
	Predicates []Predicate `yaml:"predicates,omitempty"` // attest: predicate list
	Instance   string      `yaml:"instance,omitempty"`   // log: rekor instance URL
	Policies   []string    `yaml:"policies,omitempty"`   // policy: file paths
	FailOpen   *bool       `yaml:"fail_open,omitempty"`  // policy: per-step override
}

// StepKind enumerates the recognized pipeline step types from
// SSF-SPEC-ssf-yaml §3 and the canonical DAG in SSF-ARCH-overview §7.
type StepKind string

const (
	StepSBOM   StepKind = "sbom"
	StepSign   StepKind = "sign"
	StepVerify StepKind = "verify"
	StepAttest StepKind = "attest"
	StepLog    StepKind = "log"
	StepPolicy StepKind = "policy"
)

// AllSteps lists every recognized step kind in canonical order — used by
// validation to produce useful "expected one of …" error messages.
var AllSteps = []StepKind{
	StepSBOM,
	StepSign,
	StepVerify,
	StepAttest,
	StepLog,
	StepPolicy,
}

// IsValid reports whether k is a recognized step kind.
func (k StepKind) IsValid() bool {
	for _, known := range AllSteps {
		if k == known {
			return true
		}
	}
	return false
}

// Predicate is one entry in an attest step's predicates list.
//
//   - Type "slsa-provenance": Source is empty (the predicate is auto-generated).
//   - Type "sbom":            Source must reference an existing SBOM file.
//   - Type "custom":          Source must reference a user-provided JSON predicate.
type Predicate struct {
	Type   PredicateType `yaml:"type"`
	Source string        `yaml:"source,omitempty"`
}

// PredicateType enumerates the recognized attest predicate types.
type PredicateType string

const (
	PredicateSLSAProvenance PredicateType = "slsa-provenance"
	PredicateSBOM           PredicateType = "sbom"
	PredicateCustom         PredicateType = "custom"
)

// PolicyDefaults applies policy-level defaults across every policy step.
// Per-step `fail_open` overrides this default. Per SSF-SPEC-ssf-yaml §3
// fail_open defaults to false (fail-closed) when the block is absent.
type PolicyDefaults struct {
	FailOpen bool `yaml:"fail_open"`
}

// OutputSpec controls the post-execution report.
type OutputSpec struct {
	Report string `yaml:"report,omitempty"` // path; default ssf-report.json
	Format string `yaml:"format,omitempty"` // json | text | markdown; default json
}
