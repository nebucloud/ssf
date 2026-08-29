package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/nebucloud/ssf/pkg/pipeline"
	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	var (
		dryRun    bool
		noSandbox bool
	)

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

Flags:
  --dry-run     Print the generated kiln manifest without executing.
                Useful for pre-flighting CI changes.
  --no-sandbox  Pass through to kiln to disable namespace sandbox isolation.
                Required on WSL2 and inside containers that lack the
                user-namespace permissions kiln needs.

After a real run, ssf writes a JSON report to the path declared in
ssf.yaml's output.report field (default: ssf-report.json).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPipeline(args[0], dryRun, noSandbox)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print the generated kiln manifest without executing")
	cmd.Flags().BoolVar(&noSandbox, "no-sandbox", false, "pass --no-sandbox to kiln (needed in WSL2 / restricted containers)")
	return cmd
}

func runPipeline(yamlPath string, dryRun, noSandbox bool) error {
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
		fmt.Println(string(manifestJSON))
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "ssf-run-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	// Don't auto-cleanup — leave the manifest on disk so the user can
	// inspect it after a failed run.

	manifestPath := filepath.Join(tmpDir, "pipeline.json")
	if err := os.WriteFile(manifestPath, manifestJSON, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	// Resolve the artifact's actual digest before running the pipeline so
	// the post-run report carries it whether the pipeline succeeds or
	// fails. Skipped for non-binary types in 2.4c.2 — they need their own
	// digest resolution path (registry HEAD for OCI, etc.).
	artifactDigest := resolveDigest(pl)

	bin, err := exec.LookPath("kiln")
	if err != nil {
		return fmt.Errorf(
			"kiln not on PATH — install via `cargo install kiln-cli` "+
				"or run with --dry-run to print the manifest instead "+
				"(manifest written to %s)", manifestPath,
		)
	}

	fmt.Printf("ssf: running kiln against %s\n", manifestPath)
	kilnArgs := []string{"run"}
	if noSandbox {
		kilnArgs = append(kilnArgs, "--no-sandbox")
	}
	kilnArgs = append(kilnArgs, manifestPath)

	start := time.Now()
	kilnCmd := exec.Command(bin, kilnArgs...)
	kilnCmd.Stdout = os.Stdout
	kilnCmd.Stderr = os.Stderr
	kilnErr := kilnCmd.Run()
	elapsed := time.Since(start)

	// Always emit the report — even on failure, so CI and downstream
	// consumers see what attempted to run, with the right status.
	report := buildReport(pl, artifactDigest, elapsed, kilnErr == nil)
	reportPath := pipelineReportPath(pl)
	if reportPath != "" {
		if path, err := pipeline.WriteReport(report, reportPath); err == nil {
			fmt.Printf("ssf: report written to %s\n", path)
		} else {
			// Don't fail the run because the report couldn't be
			// written — surface the issue and continue.
			fmt.Fprintf(os.Stderr, "ssf: warning: %s\n", err)
		}
	}

	if kilnErr != nil {
		return fmt.Errorf("kiln run: %w", kilnErr)
	}

	fmt.Printf("ssf: pipeline completed in %s (manifest: %s)\n", elapsed.Round(time.Millisecond), manifestPath)
	return nil
}

// resolveDigest computes the artifact's content digest when possible.
// Binary and OCI are wired; other types fall back to whatever the user
// declared in ssf.yaml or the empty string.
func resolveDigest(pl *pipeline.Pipeline) string {
	if pl.Artifact.Digest != "" {
		return pl.Artifact.Digest
	}
	switch pl.Artifact.Type {
	case artifact.TypeBinary:
		bin, err := artifact.NewBinary(pl.Artifact.Reference)
		if err == nil {
			return bin.Digest()
		}
	case artifact.TypeOCI:
		img, err := artifact.NewOCI(pl.Artifact.Reference)
		if err == nil {
			return img.Digest()
		}
	}
	return ""
}

// buildReport assembles a [pipeline.Report] from the executed pipeline. In
// 2.4c.2 we don't yet have per-step results from kiln — the per-step entries
// are placeholders showing the structure. 2.4d will parse kiln's own output
// for real per-target timings and cache info.
func buildReport(pl *pipeline.Pipeline, digest string, elapsed time.Duration, ok bool) *pipeline.Report {
	status := "passed"
	if !ok {
		status = "failed"
	}

	steps := make([]pipeline.ReportStep, 0, len(pl.Steps))
	for _, s := range pl.Steps {
		steps = append(steps, pipeline.ReportStep{
			Step:       string(s.Step),
			Status:     status,
			DurationMs: 0,
			Cached:     false,
		})
	}

	return &pipeline.Report{
		Artifact: pipeline.ReportArtifact{
			Type:      pl.Artifact.Type,
			Reference: pl.Artifact.Reference,
			Digest:    digest,
		},
		Pipeline: pipeline.ReportPipeline{
			Status:          status,
			Steps:           steps,
			TotalDurationMs: elapsed.Milliseconds(),
			CachedSteps:     0,
		},
	}
}

// pipelineReportPath returns the report destination from ssf.yaml's
// output.report, or "ssf-report.json" as the default. Empty string means the
// user explicitly opted out (output: { report: "" }).
func pipelineReportPath(pl *pipeline.Pipeline) string {
	if pl.Output != nil {
		return pl.Output.Report
	}
	return "ssf-report.json"
}
