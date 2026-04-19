package cli

import "github.com/spf13/cobra"

func newSBOMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom <artifact>",
		Short: "Generate an SBOM (SPDX or CycloneDX) for an artifact",
		Long: `Generate a Software Bill of Materials for an artifact using syft.

Output format defaults to spdx-json; use --format to switch to cyclonedx.
Without --output the SBOM is written to stdout.`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4c"),
	}
	cmd.Flags().String("format", "spdx", "output format (spdx | cyclonedx)")
	cmd.Flags().String("output", "", "output file path (default: stdout)")
	return cmd
}
