package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// missingToolError carries the missing tool's name and an install hint so the
// CLI can surface a single uniform "X not on PATH — install via …" message
// across sbom (syft), log (rekor-cli), and any future tool integrations.
type missingToolError struct {
	tool string
	hint string
}

func (e *missingToolError) Error() string {
	return fmt.Sprintf("%s not on PATH — install via %s", e.tool, e.hint)
}

// resolveTool looks up tool on PATH and returns the absolute path or a typed
// missingToolError. The hint is what gets shown to the user verbatim, so
// install commands belong here rather than scattered across handlers.
func resolveTool(tool, hint string) (string, error) {
	path, err := exec.LookPath(tool)
	if err != nil {
		return "", &missingToolError{tool: tool, hint: hint}
	}
	return path, nil
}

// runTool shells the resolved binary with args, streaming stdio to the
// caller's terminal so the tool's progress and prompts show through.
func runTool(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// IsMissingToolError unwraps to a *missingToolError if any link in the chain
// matches. Tests reach for this rather than string-matching the message.
func IsMissingToolError(err error) bool {
	var m *missingToolError
	return errors.As(err, &m)
}
