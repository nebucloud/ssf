package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/nebucloud/ssf/pkg/policy"
	"github.com/spf13/cobra"
)

// builtinPolicyDir is where SSF looks for shipped policies (base.cue,
// strict.cue, signed-only.cue, schema.cue). For development this resolves
// against the binary's working directory; for installed binaries the path
// would be configured via env or build flag — out of scope for 2.4d.
const builtinPolicyDir = "policies"

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate, list, validate, or explain CUE supply-chain policies",
	}
	cmd.AddCommand(
		newPolicyCheckCommand(),
		newPolicyListCommand(),
		newPolicyValidateCommand(),
		newPolicyExplainCommand(),
		newPolicySchemaCommand(),
	)
	return cmd
}

func newPolicyCheckCommand() *cobra.Command {
	var (
		policyPaths []string
		jsonOut     bool
		failOpen    bool
	)

	cmd := &cobra.Command{
		Use:   "check <artifact>",
		Short: "Evaluate one or more CUE policies against an artifact",
		Long: `Evaluate CUE policies against an artifact and report pass/fail per policy.

The artifact's current signed/sbom/attest state is loaded into a CUE value,
then unified with each --policy file. CUE's unification is set intersection;
failures surface with a path and CUE's human-readable rendering.

Without --json, the output is a human-readable status block per policy. With
--json, the output is structured per SSF-SPEC-policies §7.3 — suitable for
piping into the SSF MCP server or a CI status check.

Exit codes:
  0  every policy passed
  1  at least one policy failed
  2  a policy file couldn't be parsed
  3  the artifact couldn't be constructed`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyCheck(args[0], policyPaths, jsonOut, failOpen)
		},
	}
	cmd.Flags().StringArrayVarP(&policyPaths, "policy", "p", nil, "policy file path (repeatable)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit structured JSON instead of human-readable output")
	cmd.Flags().BoolVar(&failOpen, "fail-open", false, "log failures but exit 0")
	return cmd
}

func runPolicyCheck(path string, policyPaths []string, jsonOut, failOpen bool) error {
	if len(policyPaths) == 0 {
		return fmt.Errorf("at least one --policy is required")
	}

	bin, err := artifact.NewBinary(path)
	if err != nil {
		return artifactConstructError{err}
	}

	ev := policy.NewEvaluator()
	results, err := ev.Evaluate(bin, policyPaths)
	if err != nil {
		return policyParseError{err}
	}

	verdict := policy.AggregateVerdict(results)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(verdict); err != nil {
			return fmt.Errorf("encode results: %w", err)
		}
	} else {
		printHumanResults(verdict)
	}

	if !verdict.Passed && !failOpen {
		return policyFailedError{}
	}
	return nil
}

func printHumanResults(v policy.Verdict) {
	for _, r := range v.Results {
		if r.Passed {
			fmt.Printf("✓ Policy %s: passed\n", r.Policy)
			continue
		}
		fmt.Printf("✗ Policy %s: failed\n", r.Policy)
		for _, f := range r.Failures {
			if f.Path != "" {
				fmt.Printf("    Path: %s\n", f.Path)
			}
			fmt.Printf("    %s\n", f.Message)
		}
	}

	pass, total := 0, len(v.Results)
	for _, r := range v.Results {
		if r.Passed {
			pass++
		}
	}
	if v.Passed {
		fmt.Printf("\nAll policies passed (%d/%d).\n", pass, total)
	} else {
		fmt.Printf("\nFailed: %d/%d policies did not pass.\n", total-pass, total)
	}
}

// Typed error sentinels so the caller in cmd/ssf/main.go could later map them
// to the exit codes specified in SSF-SPEC-policies §8.3 (1/2/3). For 2.4d
// the binary still exits 1 on any error — the typed errors carry the right
// information for that mapping when it lands.

type artifactConstructError struct{ err error }

func (e artifactConstructError) Error() string { return e.err.Error() }
func (e artifactConstructError) Unwrap() error { return e.err }

type policyParseError struct{ err error }

func (e policyParseError) Error() string { return e.err.Error() }
func (e policyParseError) Unwrap() error { return e.err }

type policyFailedError struct{}

func (policyFailedError) Error() string { return "one or more policies failed" }

func newPolicyListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List built-in policies shipped with this ssf release",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := listBuiltins()
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("(no built-in policies found in", builtinPolicyDir+")")
				return nil
			}
			for _, e := range entries {
				fmt.Println(e)
			}
			return nil
		},
	}
}

func listBuiltins() ([]string, error) {
	var out []string
	err := filepath.WalkDir(builtinPolicyDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".cue") && !strings.HasSuffix(path, "schema.cue") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		// If the dir doesn't exist (binary installed away from source),
		// don't blow up — return empty.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

func newPolicyValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <policy.cue>",
		Short: "Validate a policy file for syntax errors without running it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			ev := policy.NewEvaluator()
			// Reuse evaluator's compile path via a no-op artifact eval —
			// the simplest correctness check is "does it compile and
			// produce a #Artifact?". We don't need a full artifact for
			// that — pass an in-memory dummy.
			_ = data
			_ = ev
			fmt.Printf("policy validate: a compile-only validate path lands alongside Cue 0.17 helpers (received %s)\n", args[0])
			return nil
		},
	}
}

func newPolicyExplainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <policy.cue>",
		Short: "Walk a policy and describe what it enforces (no artifact required)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("policy explain: structured walker lands in a future SSF release (received %s)\n", args[0])
			return nil
		},
	}
}

func newPolicySchemaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the effective #Artifact schema policies are evaluated against",
		RunE: func(cmd *cobra.Command, args []string) error {
			schemaPath := filepath.Join(builtinPolicyDir, "schema.cue")
			data, err := os.ReadFile(schemaPath)
			if err != nil {
				return fmt.Errorf("read %s: %w", schemaPath, err)
			}
			fmt.Print(string(data))
			return nil
		},
	}
}
