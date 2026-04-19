package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nebucloud/ssf/pkg/kiln"
)

// TestEmitKilnManifest_Sign covers the minimal pipeline (one sign step) and
// asserts the emitter produces a kiln manifest that round-trips through JSON
// and contains the expected target structure.
func TestEmitKilnManifest_Sign(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./out/sample"
signing:
  key: file://cosign.key
pipeline:
  - step: sign
`
	p, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	m, err := EmitKilnManifest(p)
	if err != nil {
		t.Fatalf("EmitKilnManifest: %v", err)
	}

	if got, want := m.Version, kiln.Version; got != want {
		t.Errorf("Version = %q, want %q", got, want)
	}

	signTarget, ok := m.Targets["sign"]
	if !ok {
		t.Fatalf("expected target 'sign', got %v", m.Targets)
	}
	if signTarget.Run.Interpreter != "bash" {
		t.Errorf("Run.Interpreter = %q, want bash", signTarget.Run.Interpreter)
	}
	if !strings.Contains(signTarget.Run.Code, "cosign sign-blob") {
		t.Errorf("Run.Code missing 'cosign sign-blob': %q", signTarget.Run.Code)
	}
	if !strings.Contains(signTarget.Run.Code, "cosign.key") {
		t.Errorf("Run.Code missing key path 'cosign.key': %q", signTarget.Run.Code)
	}
	if !strings.Contains(signTarget.Run.Code, "./out/sample") {
		t.Errorf("Run.Code missing artifact ref './out/sample': %q", signTarget.Run.Code)
	}
}

// TestEmitKilnManifest_DAG asserts the requires edges line up with the DAG in
// SSF-ARCH-overview §7: verify→sign, attest→{sign,sbom}, log→attest.
func TestEmitKilnManifest_DAG(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: file://cosign.key
pipeline:
  - step: sbom
    format: spdx
    output: sbom.spdx.json
  - step: sign
  - step: verify
  - step: attest
    predicates:
      - type: sbom
        source: sbom.spdx.json
  - step: log
    instance: public
`
	p, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	m, err := EmitKilnManifest(p)
	if err != nil {
		t.Fatalf("EmitKilnManifest: %v", err)
	}

	checks := []struct {
		target           string
		expectedRequires []string
	}{
		{"sbom", nil},
		{"sign", nil},
		{"verify", []string{"sign"}},
		{"attest", []string{"sign", "sbom"}},
		{"log", []string{"attest"}},
	}
	for _, c := range checks {
		got, ok := m.Targets[c.target]
		if !ok {
			t.Errorf("target %q missing from manifest", c.target)
			continue
		}
		if !sameSlice(got.Requires, c.expectedRequires) {
			t.Errorf("target %q.Requires = %v, want %v", c.target, got.Requires, c.expectedRequires)
		}
	}
}

// TestEmitKilnManifest_AttestRequiresSign rejects an ssf.yaml that asks to
// attest without first signing — without a signature there's nothing to
// attach the predicate to.
func TestEmitKilnManifest_AttestRequiresSign(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: attest
    predicates:
      - type: slsa-provenance
`
	p, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = EmitKilnManifest(p)
	if err == nil {
		t.Fatal("expected error for attest without sign, got nil")
	}
	if !strings.Contains(err.Error(), "attest step requires a prior sign step") {
		t.Errorf("error = %q, want 'attest step requires a prior sign step' substring", err)
	}
}

func TestMarshalKilnManifest_RoundTrip(t *testing.T) {
	src := `
version: "1"
artifact:
  type: binary
  reference: "./x"
signing:
  key: cosign
pipeline:
  - step: sign
`
	p, _ := Parse(strings.NewReader(src))
	m, _ := EmitKilnManifest(p)

	jsonBytes, err := MarshalKilnManifest(m)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var roundTrip kiln.Pipeline
	if err := json.Unmarshal(jsonBytes, &roundTrip); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if roundTrip.Version != m.Version {
		t.Errorf("round-tripped Version = %q, want %q", roundTrip.Version, m.Version)
	}
	if len(roundTrip.Targets) != len(m.Targets) {
		t.Errorf("round-tripped Targets count = %d, want %d", len(roundTrip.Targets), len(m.Targets))
	}
}

func TestShellQuote(t *testing.T) {
	for _, tt := range []struct {
		input string
		want  string
	}{
		{"", "''"},
		{"simple", "'simple'"},
		{"with spaces", "'with spaces'"},
		{"with'quote", `'with'\''quote'`},
		{"./path/to/file.bin", "'./path/to/file.bin'"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			if got := shellQuote(tt.input); got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func sameSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Order matters in the manifest for deterministic output, even though
	// kiln itself is order-insensitive on the requires list.
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
