package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebucloud/ssf/pkg/pipeline"
)

func TestRunInit_RoundTripsThroughParser(t *testing.T) {
	for _, ty := range []string{"binary", "oci", "crate", "npm", "blob"} {
		t.Run(ty, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "ssf.yaml")

			if err := runInit(ty, out, false); err != nil {
				t.Fatalf("runInit(%q): %v", ty, err)
			}

			// Round-trip through the parser to prove the generated
			// yaml parses + validates against the same schema the run
			// handler enforces. A drift between init and parser would
			// surface here as a validation error.
			pl, err := pipeline.ParseFile(out)
			if err != nil {
				t.Fatalf("ParseFile(generated): %v", err)
			}
			if got, want := string(pl.Artifact.Type), ty; got != want {
				t.Errorf("Artifact.Type = %q, want %q", got, want)
			}
			if pl.Signing.Key == "" {
				t.Error("Signing.Key is empty in generated template")
			}
			if len(pl.Steps) == 0 {
				t.Error("generated template has no pipeline steps")
			}
		})
	}
}

func TestRunInit_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "ssf.yaml")
	if err := os.WriteFile(out, []byte("existing"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err := runInit("binary", out, false)
	if err == nil {
		t.Fatal("expected error overwriting existing file without --force")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error %q should mention --force", err)
	}

	// With --force it should succeed and replace the content.
	if err := runInit("binary", out, true); err != nil {
		t.Fatalf("runInit with --force: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), "version: \"1\"") {
		t.Error("file content was not overwritten by --force")
	}
}

func TestRunInit_RejectsUnknownType(t *testing.T) {
	err := runInit("deb", "/tmp/will-not-be-written", false)
	if err == nil {
		t.Fatal("expected error for unknown artifact type")
	}
	if !strings.Contains(err.Error(), "not recognized") {
		t.Errorf("error %q should explain that the type is unknown", err)
	}
}
