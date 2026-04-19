package pipeline

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/nebucloud/ssf/pkg/artifact"
)

// Parse decodes ssf.yaml from r and returns a validated [Pipeline]. Validation
// runs immediately after decode so callers don't need a separate pass —
// downstream consumers (the run handler, the kiln emitter) can assume every
// field they read is structurally well-formed.
func Parse(r io.Reader) (*Pipeline, error) {
	var p Pipeline
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true) // reject unknown fields so spec drift is caught early
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("ssf.yaml: parse: %w", err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("ssf.yaml: validate: %w", err)
	}

	return &p, nil
}

// ParseFile is a convenience wrapper around [Parse] that opens path. Errors
// from the underlying file open are wrapped with the path so the user sees
// "ssf.yaml: open my-pipeline.yaml: …" rather than a bare PathError.
func ParseFile(path string) (*Pipeline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ssf.yaml: open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// Validate checks the pipeline for structural correctness — version pin,
// required fields per SSF-SPEC-ssf-yaml §3, recognized enums, per-step shape.
//
// The errors here are all of the form "field: …" so callers can present them
// flat without repeating the file context. Multiple errors aren't aggregated;
// the first violation surfaces and the rest stay hidden until it's fixed.
// That's a deliberate trade — fewer errors per round, less for the user to
// triage in one go.
func (p *Pipeline) Validate() error {
	if p.Version != SchemaVersion {
		return fmt.Errorf("version: expected %q, got %q", SchemaVersion, p.Version)
	}

	if !p.Artifact.Type.IsValid() {
		return fmt.Errorf("artifact.type: %q is not a recognized type (one of %v)", p.Artifact.Type, artifact.AllTypes)
	}
	if p.Artifact.Reference == "" {
		return fmt.Errorf("artifact.reference: must not be empty")
	}

	if p.Signing.Key == "" {
		return fmt.Errorf("signing.key: must not be empty")
	}

	if len(p.Steps) == 0 {
		return fmt.Errorf("pipeline: must contain at least one step")
	}

	for i, step := range p.Steps {
		if err := step.validate(i); err != nil {
			return err
		}
	}

	return nil
}

// validate enforces per-step shape rules. The `idx` argument is the step's
// 0-based position in the pipeline, surfaced in error messages so users can
// jump straight to the offending entry.
func (s *Step) validate(idx int) error {
	prefix := fmt.Sprintf("pipeline[%d]", idx)

	if !s.Step.IsValid() {
		return fmt.Errorf("%s.step: %q is not a recognized kind (one of %v)", prefix, s.Step, AllSteps)
	}

	switch s.Step {
	case StepSBOM:
		if s.Format == "" {
			return fmt.Errorf("%s.format: required for sbom step (spdx | cyclonedx)", prefix)
		}
		if s.Format != "spdx" && s.Format != "cyclonedx" {
			return fmt.Errorf("%s.format: %q must be spdx or cyclonedx", prefix, s.Format)
		}
		if s.Output == "" {
			return fmt.Errorf("%s.output: required for sbom step", prefix)
		}
	case StepAttest:
		if len(s.Predicates) == 0 {
			return fmt.Errorf("%s.predicates: at least one predicate required for attest step", prefix)
		}
		for j, pred := range s.Predicates {
			switch pred.Type {
			case PredicateSLSAProvenance:
				// no source needed
			case PredicateSBOM, PredicateCustom:
				if pred.Source == "" {
					return fmt.Errorf("%s.predicates[%d].source: required for type %q", prefix, j, pred.Type)
				}
			default:
				return fmt.Errorf("%s.predicates[%d].type: %q is not slsa-provenance, sbom, or custom", prefix, j, pred.Type)
			}
		}
	case StepPolicy:
		if len(s.Policies) == 0 {
			return fmt.Errorf("%s.policies: at least one policy file required for policy step", prefix)
		}
	case StepSign, StepVerify, StepLog:
		// no per-step required fields
	}

	return nil
}
