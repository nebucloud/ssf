package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebucloud/ssf/pkg/artifact"
)

// writeFixtureBinary creates a regular file under a temp dir with the given
// content. Returns the path. The signed/unsigned variants below build on top
// of this.
func writeFixtureBinary(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.bin")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// writeFixturePolicy drops a .cue file in a temp dir and returns the path.
// The policy body is wrapped in a `package fixture` declaration so multiple
// test cases can coexist in the same temp tree.
func writeFixturePolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.cue")
	full := "package fixture\n\n" + body
	if err := os.WriteFile(path, []byte(full), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestEvaluator_UnsignedBinaryFailsSignedRequirement(t *testing.T) {
	binPath := writeFixtureBinary(t, []byte("test artifact"))
	bin, err := artifact.NewBinary(binPath)
	if err != nil {
		t.Fatalf("NewBinary: %v", err)
	}

	pol := writeFixturePolicy(t, `#Artifact: {
		signed: true
		...
	}`)

	results, err := NewEvaluator().Evaluate(bin, []string{pol})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].Passed {
		t.Fatal("expected unsigned binary to fail signed:true policy")
	}
	if len(results[0].Failures) == 0 {
		t.Fatal("expected at least one failure")
	}
	// The failure should mention the conflict on `signed`.
	found := false
	for _, f := range results[0].Failures {
		if strings.Contains(f.Message, "signed") && strings.Contains(f.Message, "false and true") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a failure mentioning signed conflict, got %+v", results[0].Failures)
	}
}

func TestEvaluator_SignedBinaryPassesSignedRequirement(t *testing.T) {
	binPath := writeFixtureBinary(t, []byte("test artifact"))
	// Drop a fake .sig sidecar so constructArtifactValue marks it signed.
	// The evaluator doesn't validate the .sig contents — that's what
	// `ssf verify` is for. Policy evaluation is a state check, not a
	// crypto check (see SSF-SPEC-policies §13).
	if err := os.WriteFile(binPath+".sig", []byte("fake-base64-signature"), 0o644); err != nil {
		t.Fatalf("write .sig: %v", err)
	}

	bin, err := artifact.NewBinary(binPath)
	if err != nil {
		t.Fatalf("NewBinary: %v", err)
	}

	pol := writeFixturePolicy(t, `#Artifact: {
		signed: true
		...
	}`)

	results, err := NewEvaluator().Evaluate(bin, []string{pol})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !results[0].Passed {
		t.Fatalf("expected signed binary to pass; failures: %+v", results[0].Failures)
	}
}

func TestEvaluator_PolicyMissingArtifactDef(t *testing.T) {
	bin, err := artifact.NewBinary(writeFixtureBinary(t, []byte("x")))
	if err != nil {
		t.Fatalf("NewBinary: %v", err)
	}

	// A policy that defines no #Artifact at all — flag as configuration
	// error rather than silently passing.
	pol := writeFixturePolicy(t, `#NotArtifact: { foo: "bar" }`)
	results, err := NewEvaluator().Evaluate(bin, []string{pol})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Passed {
		t.Fatal("expected policy without #Artifact to fail")
	}
	if !strings.Contains(results[0].Failures[0].Message, "does not define #Artifact") {
		t.Errorf("expected 'does not define #Artifact' message, got %q", results[0].Failures[0].Message)
	}
}

func TestEvaluator_NonExistentPolicyFile(t *testing.T) {
	bin, err := artifact.NewBinary(writeFixtureBinary(t, []byte("x")))
	if err != nil {
		t.Fatalf("NewBinary: %v", err)
	}

	results, err := NewEvaluator().Evaluate(bin, []string{"/nonexistent/policy.cue"})
	if err != nil {
		t.Fatalf("Evaluate (a missing file is per-policy, not eval-wide): %v", err)
	}
	if results[0].Passed {
		t.Fatal("expected missing policy file to fail")
	}
	if !strings.Contains(results[0].Failures[0].Message, "read policy file") {
		t.Errorf("expected 'read policy file' in message, got %q", results[0].Failures[0].Message)
	}
}

func TestAggregateVerdict(t *testing.T) {
	for _, tt := range []struct {
		name    string
		results []Result
		want    bool
	}{
		{"empty is passing", nil, true},
		{"all pass", []Result{{Passed: true}, {Passed: true}}, true},
		{"any fail fails the verdict", []Result{{Passed: true}, {Passed: false}}, false},
		{"all fail", []Result{{Passed: false}, {Passed: false}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := AggregateVerdict(tt.results)
			if v.Passed != tt.want {
				t.Errorf("AggregateVerdict.Passed = %v, want %v", v.Passed, tt.want)
			}
		})
	}
}
