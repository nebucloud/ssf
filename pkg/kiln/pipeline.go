// Package kiln defines the JSON schema kiln-cli accepts as a pipeline manifest.
//
// Per KLN-D-02 (KLN-D-extraction-decisions §02), kiln accepts two input forms:
// a programmatic Rust builder (irrelevant to a Go consumer like SSF) and a
// JSON manifest. The shape here mirrors kiln-core's `Pipeline` struct
// one-to-one: a versioned bag of named targets, each carrying a shell
// invocation and dependency edges.
//
// Field names use snake_case via json tags so the emitted JSON matches what
// kiln-core's serde derives expect on the wire. Keep this file synchronized
// with the canonical Rust types at
// https://github.com/nebucloud/kiln/blob/main/crates/kiln-core/src/target.rs —
// adding a field requires touching both projects.
package kiln

// Version is the only schema version kiln 0.1.x recognizes for the JSON
// manifest. Same value the Rust enum's `#[serde(rename = "1")]` produces.
const Version = "1"

// Pipeline is the top-level kiln pipeline manifest.
type Pipeline struct {
	Version  string            `json:"version"`
	Targets  map[string]Target `json:"targets"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Target is one node in the pipeline DAG. Requires references other target
// names (must exist in the same Pipeline.Targets map). Inputs and Outputs are
// human-readable name lists used by kiln for cache-key composition and report
// rendering — the actual values are passed through environment.
type Target struct {
	Run      ShellBlock `json:"run"`
	Cleanup  *ShellBlock `json:"cleanup,omitempty"`
	Requires []string   `json:"requires,omitempty"`
	Inputs   []string   `json:"inputs,omitempty"`
	Outputs  []string   `json:"outputs,omitempty"`
}

// ShellBlock is what kiln executes for a target. The interpreter must be on
// PATH inside kiln's sandbox (bash, sh, python3, etc.); the code is the
// script source kiln writes to a temp file and dispatches.
type ShellBlock struct {
	Interpreter string `json:"interpreter"`
	Code        string `json:"code"`
}
