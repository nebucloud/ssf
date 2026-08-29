package artifact

import (
	"fmt"
	"os"
	"strings"
)

// Open loads an [Artifact] from a CLI-style reference.
//
// Dispatch:
//   - Existing regular file path → [NewBinary]
//   - Otherwise → [NewOCI] (registry reference)
//
// Callers that already know the type should use NewBinary / NewOCI directly.
func Open(reference string) (Artifact, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return nil, fmt.Errorf("artifact: empty reference")
	}

	if info, err := os.Stat(reference); err == nil && info.Mode().IsRegular() {
		return NewBinary(reference)
	}

	return NewOCI(reference)
}
