package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/nebucloud/ssf/pkg/pipeline"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "run <ssf.yaml>",
		Short: "Execute the supply-chain pipeline declared in an ssf.yaml file",
		Long: `Parse ssf.yaml, emit a kiln pipeline manifest (JSON), and invoke kiln to
execute it hermetically.

Per KLN-D-02, ssf emits the manifest as JSON conforming to kiln's Pipeline
type — kiln then handles toposort, parallel wave extraction, sandbox
isolation, and content-addressed caching. Tools (cosign, syft, cue,
rekor-cli) must be on PATH for v1; World Builder–provided tool versions
land in a future phase.

With --dry-run, ssf prints the generated manifest without invoking kiln —
useful for debugging or pre-flighting CI changes.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPipeline(args[0], dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the generated kiln manifest without executing")
	return cmd
}

func runPipeline(yamlPath string, dryRun bool) error {
	pl, err := pipeline.ParseFile(yamlPath)
	if err != nil {
		return err
	}

	manifest, err := pipeline.EmitKilnManifest(pl)
	if err != nil {
		return fmt.Errorf("emit kiln manifest: %w", err)
	}

	manifestJSON, err := pipeline.MarshalKilnManifest(manifest)
	if err != nil {
		return fmt.Errorf("marshal kiln manifest: %w", err)
	}

	if dryRun {
		// Print to stdout so callers can pipe to jq, kiln validate, etc.
		fmt.Println(string(manifestJSON))
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "ssf-run-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	// Don't auto-cleanup — leave the manifest on disk so the user can
	// inspect it after a failed run. The temp dir lives in /tmp which
	// the OS sweeps periodically.

	manifestPath := tmpDir + "/pipeline.json"
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	bin, err := exec.LookPath("kiln")
	if err != nil {
		return fmt.Errorf(
			"kiln not on PATH — install via `cargo install kiln-cli` "+
				"or run with --dry-run to print the manifest instead "+
				"(manifest written to %s)", manifestPath,
		)
	}

	fmt.Printf("ssf: running kiln against %s\n", manifestPath)
	kilnCmd := exec.Command(bin, "run", manifestPath)
	kilnCmd.Stdout = os.Stdout
	kilnCmd.Stderr = os.Stderr
	if err := kilnCmd.Run(); err != nil {
		return fmt.Errorf("kiln run: %w", err)
	}

	fmt.Printf("ssf: pipeline completed (manifest: %s)\n", manifestPath)
	return nil
}
