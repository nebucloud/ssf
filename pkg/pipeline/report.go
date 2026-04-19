package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nebucloud/ssf/pkg/artifact"
)

// Report is the post-execution summary `ssf run` writes to disk per
// SSF-SPEC-ssf-yaml §8. The shape is the agreed wire form for downstream
// consumers (CI status checks, the SSF MCP server, the Conductor agents) so
// every field is JSON-tagged with the canonical key.
type Report struct {
	Artifact ReportArtifact `json:"artifact"`
	Pipeline ReportPipeline `json:"pipeline"`
	Policy   *ReportPolicy  `json:"policy,omitempty"`

	// ISO 8601 timestamp when the run completed (whether passed or failed).
	Timestamp string `json:"timestamp"`
}

// ReportArtifact echoes the artifact spec the pipeline secured. Digest is
// resolved at run time (after the artifact is loaded), so it appears in the
// report even when the input ssf.yaml left the field blank for auto-detection.
type ReportArtifact struct {
	Type      artifact.Type `json:"type"`
	Reference string        `json:"reference"`
	Digest    string        `json:"digest,omitempty"`
}

// ReportPipeline summarizes the per-step outcomes. Status is "passed" if every
// step succeeded; "failed" if any step or policy failed. TotalDurationMs is
// wall-clock from kiln invocation start to completion.
type ReportPipeline struct {
	Status          string       `json:"status"`
	Steps           []ReportStep `json:"steps"`
	TotalDurationMs int64        `json:"total_duration_ms"`
	CachedSteps     int          `json:"cached_steps"`
}

// ReportStep is one entry in the per-step result list. Cached reflects whether
// kiln short-circuited the target on a content-addressed cache hit.
type ReportStep struct {
	Step       string `json:"step"`
	Status     string `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	Cached     bool   `json:"cached"`
}

// ReportPolicy records the policy step results when one ran. Lands meaningfully
// in 2.4d once the CUE evaluator is wired; in 2.4c.2 it stays nil.
type ReportPolicy struct {
	Evaluated []string             `json:"evaluated,omitempty"`
	Passed    bool                 `json:"passed"`
	Results   []ReportPolicyResult `json:"results,omitempty"`
}

// ReportPolicyResult is one row in the policy results table.
type ReportPolicyResult struct {
	Policy string `json:"policy"`
	Passed bool   `json:"passed"`
}

// WriteReport serializes the report and writes it to path. Returns the
// absolute file path so callers can echo it to the terminal for the user.
func WriteReport(r *Report, path string) (string, error) {
	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}
