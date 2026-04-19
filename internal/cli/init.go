package cli

import "github.com/spf13/cobra"

func newInitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a starter ssf.yaml in the current directory",
		Long: `Generate a starter ssf.yaml tailored to a given artifact type.

With --type, the generated file includes type-appropriate defaults (e.g., a
container reference for oci, a binary path for binary). Without --type, ssf
infers from the project layout when possible and falls back to prompting.`,
		RunE: notImplemented("2.4c"),
	}
	cmd.Flags().String("type", "", "artifact type for the generated pipeline (oci | binary | crate | npm | derivation | blob)")
	return cmd
}
