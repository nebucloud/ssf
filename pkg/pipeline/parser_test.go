package pipeline

import (
	"strings"
	"testing"
)

func TestParse_MinimalValid(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./target/release/ssf"
signing:
  key: file://cosign.key
pipeline:
  - step: sign
`
	p, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := p.Artifact.Reference, "./target/release/ssf"; got != want {
		t.Errorf("Artifact.Reference = %q, want %q", got, want)
	}
	if len(p.Steps) != 1 || p.Steps[0].Step != StepSign {
		t.Errorf("Steps = %v, want [sign]", p.Steps)
	}
}

func TestParse_FullSchema(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./out/sample"
  metadata:
    debug_symbols: "false"
signing:
  key: file://cosign.key
tools:
  cosign: "2.4.0"
pipeline:
  - step: sbom
    format: spdx
    output: sbom.spdx.json
  - step: sign
  - step: verify
  - step: attest
    predicates:
      - type: slsa-provenance
      - type: sbom
        source: sbom.spdx.json
  - step: log
    instance: public
  - step: policy
    policies:
      - policies/base.cue
policy:
  fail_open: false
output:
  report: ssf-report.json
  format: json
`
	p, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got, want := len(p.Steps), 6; got != want {
		t.Fatalf("len(Steps) = %d, want %d", got, want)
	}
	if p.Tools["cosign"] != "2.4.0" {
		t.Errorf("Tools[cosign] = %q, want 2.4.0", p.Tools["cosign"])
	}
	if p.Output == nil || p.Output.Format != "json" {
		t.Errorf("Output = %+v, want format=json", p.Output)
	}
}

func TestParse_RejectsUnknownFields(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./x"
  flavor: spicy
signing:
  key: cosign
pipeline:
  - step: sign
`
	_, err := Parse(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected error on unknown field 'flavor', got nil")
	}
}

func TestValidate_Errors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name: "wrong version",
			yaml: `
version: "2"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: sign
`,
			wantSub: `version: expected "1"`,
		},
		{
			name: "unknown artifact type",
			yaml: `
version: "1"
artifact:
  type: deb
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: sign
`,
			wantSub: "artifact.type: ",
		},
		{
			name: "missing signing key",
			yaml: `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: ""
pipeline:
  - step: sign
`,
			wantSub: "signing.key: must not be empty",
		},
		{
			name: "empty pipeline",
			yaml: `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline: []
`,
			wantSub: "pipeline: must contain at least one step",
		},
		{
			name: "sbom missing format",
			yaml: `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: sbom
    output: sbom.json
`,
			wantSub: "pipeline[0].format: required for sbom step",
		},
		{
			name: "attest with no predicates",
			yaml: `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: sign
  - step: attest
`,
			wantSub: "pipeline[1].predicates: at least one predicate required",
		},
		{
			name: "policy with no files",
			yaml: `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: policy
`,
			wantSub: "pipeline[0].policies: at least one policy file required",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}
