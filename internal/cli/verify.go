package cli

import "github.com/spf13/cobra"

func newVerifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <artifact>",
		Short: "Verify an artifact signature with cosign",
		Long: `Verify an artifact signature using cosign verify or cosign verify-blob.

Mirrors the dispatch in 'ssf sign': OCI artifacts use cosign verify against
the sibling signature in the registry; everything else uses cosign verify-blob
against the conventionally-located <path>.sig file.

Without --key, ssf uses the same Cosign default key discovery as 'ssf sign'.`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4b"),
	}
	cmd.Flags().String("key", "", "verification key reference (cosign | vault://path | fulcio | file://path)")
	return cmd
}
