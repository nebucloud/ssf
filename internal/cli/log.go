package cli

import "github.com/spf13/cobra"

func newLogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log <artifact>",
		Short: "Record the artifact's signature/attestation to a Rekor transparency log",
		Long: `Upload the artifact's signature and attestation to a Rekor transparency log.

Defaults to the public Sigstore Rekor instance. Use --instance to point at a
self-hosted Rekor URL for air-gapped or compliance-sensitive deployments.`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4c"),
	}
	cmd.Flags().String("instance", "public", "rekor instance (public | <https URL>)")
	return cmd
}
