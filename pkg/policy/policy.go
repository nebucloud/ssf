// Package policy evaluates CUE policies against an artifact's current state.
//
// Per SSF-SPEC-policies §4, evaluation is unification (`&`): the artifact's
// known fields (loaded from sidecar files like .sig, the SBOM, the
// attestation) merge with the policy's constraints. The merge succeeds if
// every constraint is satisfied; otherwise CUE produces a typed error with a
// field path that the [Result] structure surfaces verbatim.
//
// The policy library lives in policies/ (schema.cue, base.cue, strict.cue);
// projects supply their own custom policies via the same shape. Evaluation is
// stateless — every call to [Evaluator.Evaluate] is a fresh load + unify, no
// caching or shared CUE context across runs.
package policy

import "github.com/nebucloud/ssf/pkg/artifact"

// Result is one policy's verdict against an artifact, plus any structured
// failures CUE surfaced during unification.
//
// Passed mirrors the spec's pass/fail semantics: every constraint in the
// policy unified successfully against the artifact value. Failures are flat
// — one entry per leaf constraint that didn't satisfy. Path matches CUE's
// dot-notation field path so users can map back to the source line.
type Result struct {
	// Policy is the file path the user supplied via -p (or the built-in
	// name, when that lands).
	Policy string `json:"policy"`

	// Passed is true if every constraint unified.
	Passed bool `json:"passed"`

	// Failures is empty when Passed is true. When Passed is false, one
	// entry per leaf constraint that failed unification.
	Failures []Failure `json:"failures,omitempty"`
}

// Failure is one leaf-level unification failure. Path / Expected / Actual
// shape matches the JSON contract in SSF-SPEC-policies §7.3 so external
// consumers (CI status lines, the eventual Policy agent in Conductor) parse
// uniformly.
type Failure struct {
	Path     string `json:"path"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Message  string `json:"message"`
}

// Verdict is the aggregate outcome across one or more [Result]s.
type Verdict struct {
	Passed  bool     `json:"passed"`
	Results []Result `json:"results"`
}

// AggregateVerdict folds per-policy results into an aggregate. Passed is true
// only when every individual policy passed.
func AggregateVerdict(results []Result) Verdict {
	v := Verdict{Passed: true, Results: results}
	for _, r := range results {
		if !r.Passed {
			v.Passed = false
		}
	}
	return v
}

// Evaluator evaluates one or more policy files against an artifact.
type Evaluator interface {
	// Evaluate loads each path in policyPaths, unifies it with the artifact's
	// current state, and returns one [Result] per policy. The slice order
	// matches the input order so callers can correlate by index.
	//
	// # Errors
	//
	// Returns an error only for policy-loading failures (file not found,
	// CUE syntax error). A constraint failure is part of the [Result], not
	// an error — that distinction matches the CLI's exit-code mapping in
	// SSF-SPEC-policies §8.3.
	Evaluate(art artifact.Artifact, policyPaths []string) ([]Result, error)
}
