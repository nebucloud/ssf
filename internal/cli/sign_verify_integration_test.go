package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSignVerify_RoundTrip exercises the Phase 2.4b exit criterion end-to-end:
// generate an ephemeral cosign keypair, sign a fixture binary, verify the
// signature.
//
// Skipped if cosign isn't on PATH so the rest of the suite still runs in
// minimal CI environments. Run as a normal `go test ./...` when cosign is
// installed; the test owns its own temp dir and key material.
func TestSignVerify_RoundTrip(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not on PATH — install via `go install github.com/sigstore/cosign/v2/cmd/cosign@latest`")
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "sample-binary")
	if err := os.WriteFile(binPath, []byte("the artifact under test"), 0o755); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Generate an ephemeral cosign keypair in the temp dir. Cosign writes
	// cosign.key + cosign.pub to its cwd, so cd in for the call. Use an
	// empty password (COSIGN_PASSWORD="") so the call is non-interactive.
	t.Setenv("COSIGN_PASSWORD", "")
	keyDir := t.TempDir()
	cmd := exec.Command("cosign", "generate-key-pair")
	cmd.Dir = keyDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cosign generate-key-pair: %v\n%s", err, out)
	}

	privKey := filepath.Join(keyDir, "cosign.key")
	pubKey := filepath.Join(keyDir, "cosign.pub")

	t.Run("sign", func(t *testing.T) {
		if err := runSign(binPath, "file://"+privKey); err != nil {
			t.Fatalf("runSign: %v", err)
		}
		sigPath := binPath + ".sig"
		if _, err := os.Stat(sigPath); err != nil {
			t.Fatalf("expected signature at %s: %v", sigPath, err)
		}
	})

	t.Run("verify", func(t *testing.T) {
		// Verification needs both --insecure-ignore-tlog (no Rekor in
		// 2.4b) and the public key. We don't expose the tlog flag on
		// the SSF surface yet, so set it via env for the cosign process.
		t.Setenv("COSIGN_EXPERIMENTAL", "0")
		t.Setenv("TUF_ROOT", t.TempDir()) // isolate from any global TUF state

		if err := runVerify(binPath, "file://"+pubKey); err != nil {
			// In Phase 2.4b cosign defaults to verifying against the
			// transparency log, which we haven't configured. Surface
			// this so 2.4c can decide whether to add an --insecure flag
			// or wire Rekor properly.
			t.Logf("note: cosign verify-blob may need --insecure-ignore-tlog if Rekor is unreachable")
			t.Fatalf("runVerify: %v", err)
		}
	})
}

func TestTranslateKey(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty defaults", "", "", false},
		{"explicit cosign", "cosign", "", false},
		{"file scheme stripped", "file:///tmp/cosign.key", "/tmp/cosign.key", false},
		{"vault transit passthrough", "vault://transit/nebucloud-signing", "vault://transit/nebucloud-signing", false},
		{"fulcio rejected in 2.4b", "fulcio", "", true},
		{"unknown scheme passthrough", "awskms:///alias/my-key", "awskms:///alias/my-key", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := translateKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("translateKey(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("translateKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
