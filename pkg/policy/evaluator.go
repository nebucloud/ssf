package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"cuelang.org/go/cue/errors"

	"github.com/nebucloud/ssf/pkg/artifact"
)

// CUEEvaluator is the production [Evaluator] implementation. It uses
// cuelang.org/go to load policy files, build an artifact CUE value from the
// runtime state, and unify the two.
//
// Construction is cheap (no I/O, no compilation) — instantiate one per
// invocation. CUE contexts are not safe for concurrent use across goroutines,
// so don't share an Evaluator across parallel evaluations either.
type CUEEvaluator struct {
	ctx *cue.Context
}

// NewEvaluator returns a CUE-backed [Evaluator]. Holds nothing that needs
// cleanup — the underlying cue.Context lives for the duration of evaluations.
func NewEvaluator() *CUEEvaluator {
	return &CUEEvaluator{ctx: cuecontext.New()}
}

// Evaluate implements [Evaluator]. Loads each policy file, unifies it with
// the artifact value, and collects the per-policy results. A leaf-level
// failure becomes a [Failure] entry on the result; a syntactically-broken
// policy file or unreadable artifact becomes a top-level error.
func (e *CUEEvaluator) Evaluate(art artifact.Artifact, policyPaths []string) ([]Result, error) {
	value, err := constructArtifactValue(art)
	if err != nil {
		return nil, fmt.Errorf("policy: build artifact value: %w", err)
	}

	artJSON, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal artifact value: %w", err)
	}

	artCUE := e.ctx.CompileBytes(artJSON, cue.Filename("artifact.json"))
	if err := artCUE.Err(); err != nil {
		return nil, fmt.Errorf("policy: load artifact value into CUE: %w", err)
	}

	results := make([]Result, 0, len(policyPaths))
	for _, p := range policyPaths {
		results = append(results, e.evaluatePolicy(p, artCUE))
	}
	return results, nil
}

func (e *CUEEvaluator) evaluatePolicy(path string, artifactValue cue.Value) Result {
	src, err := os.ReadFile(path)
	if err != nil {
		return Result{
			Policy: path,
			Passed: false,
			Failures: []Failure{{
				Path:    path,
				Message: fmt.Sprintf("read policy file: %v", err),
			}},
		}
	}

	// Each policy is compiled standalone — we don't try to unify the
	// schema package's #Artifact with the policy here because most
	// policies in 2.4d are written without `package` declarations and
	// reach for #Artifact at the top level. CUE's compile-time error
	// surface is plenty for catching bad policies in 2.4d; the richer
	// "policy library + import resolution" lands when projects start
	// composing custom policies via base/strict imports.
	policyCUE := e.ctx.CompileBytes(src, cue.Filename(path))
	if err := policyCUE.Err(); err != nil {
		return Result{
			Policy: path,
			Passed: false,
			Failures: cueErrorsToFailures(err),
		}
	}

	// Look up #Artifact in the policy. Policies without a #Artifact
	// definition can't constrain anything — flag them as a configuration
	// error rather than silently passing.
	policyArtifact := policyCUE.LookupPath(cue.ParsePath("#Artifact"))
	if !policyArtifact.Exists() {
		return Result{
			Policy: path,
			Passed: false,
			Failures: []Failure{{
				Path:    "",
				Message: "policy does not define #Artifact",
			}},
		}
	}

	unified := policyArtifact.Unify(artifactValue)
	if err := unified.Err(); err != nil {
		return Result{
			Policy: path,
			Passed: false,
			Failures: cueErrorsToFailures(err),
		}
	}

	// Validate against concrete required fields — Unify alone returns no
	// error on under-specification, so we need an explicit Validate to
	// catch missing-required-field cases.
	if err := unified.Validate(cue.Concrete(true), cue.Final()); err != nil {
		return Result{
			Policy: path,
			Passed: false,
			Failures: cueErrorsToFailures(err),
		}
	}

	return Result{Policy: path, Passed: true}
}

// cueErrorsToFailures flattens a (possibly nested) CUE error into one
// [Failure] per leaf. The path comes from the error's location and the
// message is CUE's human-readable rendering.
func cueErrorsToFailures(err error) []Failure {
	var out []Failure
	for _, e := range errors.Errors(err) {
		path := strings.Join(e.Path(), ".")
		out = append(out, Failure{
			Path:    path,
			Message: e.Error(),
		})
	}
	if len(out) == 0 {
		out = append(out, Failure{Message: err.Error()})
	}
	return out
}
