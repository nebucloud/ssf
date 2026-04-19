package cli

import (
	"fmt"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/spf13/cobra"
)

func newSBOMCommand() *cobra.Command {
	var (
		format string
		output string
	)

	cmd := &cobra.Command{
		Use:   "sbom <artifact>",
		Short: "Generate an SBOM (SPDX or CycloneDX) for an artifact",
		Long: `Generate a Software Bill of Materials for an artifact using syft.

Output format defaults to spdx-json; use --format cyclonedx for CycloneDX.
Without --output the SBOM is written to stdout (so the call composes cleanly
with shell pipelines).

Phase 2.4c.2 only handles the binary artifact type via syft. Other types
land alongside their dispatch (oci uses syft against the registry ref,
crate/npm syft against a downloaded tarball, etc.).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSBOM(args[0], format, output)
		},
	}
	cmd.Flags().StringVar(&format, "format", "spdx", "output format (spdx | cyclonedx)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file path (default: stdout)")
	return cmd
}

func runSBOM(path, format, output string) error {
	if format != "spdx" && format != "cyclonedx" {
		return fmt.Errorf("--format %q must be spdx or cyclonedx", format)
	}

	bin, err := artifact.NewBinary(path)
	if err != nil {
		return err
	}

	syft, err := resolveTool("syft", "https://github.com/anchore/syft#installation")
	if err != nil {
		return err
	}

	syftFormat := format + "-json"
	args := []string{bin.Reference(), "-o", syftFormat}
	if output != "" {
		args = append(args, "--file", output)
	}

	if err := runTool(syft, args...); err != nil {
		return fmt.Errorf("syft: %w", err)
	}

	if output != "" {
		fmt.Printf("sbom (%s) written to %s\n", format, output)
		fmt.Printf("  artifact: %s\n", bin.Reference())
		fmt.Printf("  digest:   %s\n", bin.Digest())
	}
	return nil
}
