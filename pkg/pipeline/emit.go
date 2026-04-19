package pipeline

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nebucloud/ssf/pkg/kiln"
)

// EmitKilnManifest translates a validated SSF pipeline into the kiln pipeline
// manifest JSON shape per KLN-D-02. Each ssf step becomes a named kiln target;
// implicit dependencies (sbom→attest, sign→verify, attest→log, etc.) are
// materialized as kiln `requires` edges so kiln's planner can extract waves.
//
// The emitted shell commands invoke FRSCA tools (cosign, syft, rekor-cli) by
// bare name. Per SSF-ARCH-overview §8.1, the v1 contract is "tools must be on
// PATH" — kiln inherits PATH into its sandbox and the bash run blocks call the
// tools by name. World Builder–provisioned tools land in a future phase.
//
// Returns an error if a step references a state that no earlier step produced
// (e.g., an attest step listing an sbom predicate when no sbom step ran).
func EmitKilnManifest(p *Pipeline) (*kiln.Pipeline, error) {
	manifest := &kiln.Pipeline{
		Version: kiln.Version,
		Targets: make(map[string]kiln.Target),
		Metadata: map[string]string{
			"ssf.artifact.type":      string(p.Artifact.Type),
			"ssf.artifact.reference": p.Artifact.Reference,
		},
	}

	// Track which steps actually produced their canonical output so later
	// steps can declare correct `requires` edges. Map keyed by StepKind so
	// we can ask "did sign happen?" without scanning the slice.
	produced := make(map[StepKind]string) // stepKind → target name

	// Per-kind occurrence count drives the canonical naming scheme: the
	// first instance of a kind gets the bare kind name ("sign"), subsequent
	// instances get "_N" suffixes ("sign_2"). Indexing by slice position
	// instead would surprise users who put sign at position 1.
	counts := make(map[StepKind]int)

	// Scratch state shared across emit functions: artifact ref + signing
	// key both come from top-level pipeline fields, not per-step.
	state := emitState{
		artifactRef: p.Artifact.Reference,
		signingKey:  p.Signing.Key,
		sbomPath:    "", // set by sbom step if it runs
	}

	for _, step := range p.Steps {
		occurrence := counts[step.Step]
		name := canonicalName(step.Step, occurrence)
		counts[step.Step]++

		target, err := emitStep(step, name, &state, produced)
		if err != nil {
			return nil, err
		}
		manifest.Targets[name] = target
		produced[step.Step] = name
	}

	return manifest, nil
}

// emitState carries values that flow between steps — the artifact reference
// and signing key (set once at pipeline scope) and the sbom output path (set
// by the sbom step, consumed by attest steps that include an sbom predicate).
type emitState struct {
	artifactRef string
	signingKey  string
	sbomPath    string
}

// canonicalName returns the kiln target name for a given step. The first
// occurrence of a kind gets the bare name (e.g., "sign"); subsequent
// occurrences are suffixed with their occurrence index so names stay unique.
// `occurrence` is the zero-based count of prior steps with the same kind.
func canonicalName(kind StepKind, occurrence int) string {
	if occurrence == 0 {
		return string(kind)
	}
	return fmt.Sprintf("%s_%d", kind, occurrence+1)
}

func emitStep(step Step, name string, state *emitState, produced map[StepKind]string) (kiln.Target, error) {
	switch step.Step {
	case StepSBOM:
		state.sbomPath = step.Output
		return kiln.Target{
			Run: kiln.ShellBlock{
				Interpreter: "bash",
				Code:        fmt.Sprintf("syft %s -o %s-json > %s", shellQuote(state.artifactRef), step.Format, shellQuote(step.Output)),
			},
			Inputs:  []string{"artifact_ref"},
			Outputs: []string{"sbom_path"},
		}, nil

	case StepSign:
		return kiln.Target{
			Run: kiln.ShellBlock{
				Interpreter: "bash",
				Code:        fmt.Sprintf("cosign sign-blob --yes --key %s --output-signature %s.sig %s", shellQuote(translateKeyForShell(state.signingKey)), shellQuote(state.artifactRef), shellQuote(state.artifactRef)),
			},
			Inputs:  []string{"artifact_ref", "signing_key"},
			Outputs: []string{"signature"},
		}, nil

	case StepVerify:
		signTarget, ok := produced[StepSign]
		if !ok {
			return kiln.Target{}, fmt.Errorf("verify step requires a prior sign step")
		}
		return kiln.Target{
			Requires: []string{signTarget},
			Run: kiln.ShellBlock{
				Interpreter: "bash",
				Code:        fmt.Sprintf("cosign verify-blob --key %s --signature %s.sig %s", shellQuote(translateKeyForShell(state.signingKey)), shellQuote(state.artifactRef), shellQuote(state.artifactRef)),
			},
			Inputs: []string{"artifact_ref", "signing_key"},
		}, nil

	case StepAttest:
		signTarget, ok := produced[StepSign]
		if !ok {
			return kiln.Target{}, fmt.Errorf("attest step requires a prior sign step")
		}
		requires := []string{signTarget}
		// If any predicate references the sbom output, add the sbom
		// step as a dependency too. That keeps the DAG accurate even
		// when the user authored the steps in non-canonical order.
		var predLines []string
		for _, pred := range step.Predicates {
			switch pred.Type {
			case PredicateSLSAProvenance:
				// kiln/cosign generates this from build env; we don't
				// have provenance generation yet — emit a stubbed line
				// the user can replace until 2.4d wires kiln materials.
				predLines = append(predLines, "# attest: slsa-provenance predicate generation lands in a future phase")
			case PredicateSBOM:
				if sbomTarget, ok := produced[StepSBOM]; ok {
					requires = append(requires, sbomTarget)
				} else {
					return kiln.Target{}, fmt.Errorf("attest step references sbom predicate but no prior sbom step ran")
				}
				predLines = append(predLines,
					fmt.Sprintf("cosign attest-blob --yes --key %s --predicate %s --type spdxjson %s",
						shellQuote(translateKeyForShell(state.signingKey)),
						shellQuote(pred.Source),
						shellQuote(state.artifactRef)))
			case PredicateCustom:
				predLines = append(predLines,
					fmt.Sprintf("cosign attest-blob --yes --key %s --predicate %s --type custom %s",
						shellQuote(translateKeyForShell(state.signingKey)),
						shellQuote(pred.Source),
						shellQuote(state.artifactRef)))
			}
		}
		return kiln.Target{
			Requires: requires,
			Run: kiln.ShellBlock{
				Interpreter: "bash",
				Code:        strings.Join(predLines, "\n"),
			},
			Inputs:  []string{"artifact_ref", "sbom_path"},
			Outputs: []string{"attestation"},
		}, nil

	case StepLog:
		attestTarget, ok := produced[StepAttest]
		if !ok {
			return kiln.Target{}, fmt.Errorf("log step requires a prior attest step")
		}
		instance := step.Instance
		if instance == "" || instance == "public" {
			instance = "https://rekor.sigstore.dev"
		}
		return kiln.Target{
			Requires: []string{attestTarget},
			Run: kiln.ShellBlock{
				Interpreter: "bash",
				Code:        fmt.Sprintf("rekor-cli upload --rekor_server %s --artifact %s --type intoto", shellQuote(instance), shellQuote(state.artifactRef)),
			},
			Inputs: []string{"artifact_ref", "attestation"},
		}, nil

	case StepPolicy:
		// Policy depends on whatever earlier steps populated the state
		// the policies might reference. We conservatively require sbom
		// and attest if they ran — it's better to over-serialize than to
		// race them.
		var requires []string
		if t, ok := produced[StepSBOM]; ok {
			requires = append(requires, t)
		}
		if t, ok := produced[StepAttest]; ok {
			requires = append(requires, t)
		}
		var policyArgs []string
		for _, p := range step.Policies {
			policyArgs = append(policyArgs, shellQuote(p))
		}
		return kiln.Target{
			Requires: requires,
			Run: kiln.ShellBlock{
				Interpreter: "bash",
				// Real CUE invocation lands in 2.4d alongside the
				// policy schema work; for now emit a placeholder the
				// user can pre-flight before the evaluator ships.
				Code: fmt.Sprintf("# policy evaluation lands in NEB-PLAN-phasing 2.4d\necho 'cue eval %s'", strings.Join(policyArgs, " ")),
			},
			Inputs: []string{"sbom_path", "attestation", "policy_files"},
		}, nil
	}

	return kiln.Target{}, fmt.Errorf("emit: unhandled step kind %q", step.Step)
}

// translateKeyForShell maps SSF's --key surface (the same one in
// SSF-SPEC-ssf-yaml signing.key) to what cosign's --key flag accepts when
// shelled from a bash run block. Mirrors internal/cli/cosign.go's translateKey
// — the two would ideally share an implementation, but cli/cosign.go lives
// under internal/ for binary privacy and this package is public, so we
// duplicate the table rather than carving out a shared util.
func translateKeyForShell(raw string) string {
	switch {
	case raw == "" || raw == "cosign":
		return "" // cosign default key discovery
	case strings.HasPrefix(raw, "file://"):
		return strings.TrimPrefix(raw, "file://")
	case raw == "fulcio":
		return "" // keyless lands in a future phase; fail at parse-time would be better
	default:
		return raw
	}
}

// shellQuote wraps a value in single quotes for safe interpolation into a
// bash run block, escaping any embedded single quotes via the standard
// '\''-and-restart trick. The kiln sandbox uses bash specifically (per kiln-
// core ShellBlock), so we don't need to handle other quoting styles.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// Escape ' as '\'' (close single, escaped single, reopen).
	escaped := strings.ReplaceAll(s, "'", `'\''`)
	return "'" + escaped + "'"
}

// MarshalKilnManifest serializes a kiln pipeline as pretty-printed JSON,
// suitable for writing to a temp file and handing to `kiln run`.
func MarshalKilnManifest(m *kiln.Pipeline) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
