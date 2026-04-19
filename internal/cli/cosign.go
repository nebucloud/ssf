package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrCosignMissing is returned when cosign isn't on PATH. Surfaced verbatim by
// the sign / verify handlers so users get an actionable install hint instead
// of a generic exec.ErrNotFound.
var ErrCosignMissing = errors.New(
	"cosign not found on PATH — install via " +
		"`go install github.com/sigstore/cosign/v2/cmd/cosign@latest` or " +
		"see https://docs.sigstore.dev/cosign/installation",
)

// resolveCosign locates the cosign binary on PATH. The returned absolute path
// is what we hand to exec.Command, avoiding race-on-PATH-mutation between
// lookup and execution.
func resolveCosign() (string, error) {
	path, err := exec.LookPath("cosign")
	if err != nil {
		return "", ErrCosignMissing
	}
	return path, nil
}

// translateKey converts an SSF-style --key value to the form cosign's CLI
// accepts. SSF supports the same surface as ssf.yaml signing.key
// (SSF-SPEC-ssf-yaml §3) so users see one consistent shape across CLI and
// declarative pipeline configs:
//
//	cosign            → empty string, lets cosign use its default key discovery
//	                    (env var, KMS, prompt) — same as cosign sign-blob with no --key
//	file://path       → path (cosign accepts a bare filesystem path)
//	vault://transit/k → vault://transit/k passed through (Vault transit URI)
//	fulcio            → empty string + future --identity flag (keyless; not in 2.4b)
//	<anything else>   → passed through unchanged so users can pin to specific
//	                    KMS URIs without ssf having to enumerate every backend
func translateKey(raw string) (string, error) {
	switch {
	case raw == "" || raw == "cosign":
		return "", nil
	case strings.HasPrefix(raw, "file://"):
		return strings.TrimPrefix(raw, "file://"), nil
	case raw == "fulcio":
		return "", fmt.Errorf("--key fulcio (keyless) is not supported in Phase 2.4b")
	default:
		return raw, nil
	}
}

// runCosign invokes cosign with the given args, streaming stdout/stderr to the
// caller's terminal. Returns the wrapped exit error if cosign fails so the
// caller can chain it as a single error to user-visible output.
func runCosign(args ...string) error {
	bin, err := resolveCosign()
	if err != nil {
		return err
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cosign %s failed: %w", args[0], err)
	}
	return nil
}
