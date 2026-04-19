package cli

import (
	"fmt"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/spf13/cobra"
)

func newLogCommand() *cobra.Command {
	var instance string

	cmd := &cobra.Command{
		Use:   "log <artifact>",
		Short: "Record the artifact's signature/attestation to a Rekor transparency log",
		Long: `Upload the artifact's signature to a Rekor transparency log via rekor-cli.

Defaults to the public Sigstore Rekor instance. Use --instance to point at a
self-hosted Rekor URL for air-gapped or compliance-sensitive deployments.

The artifact's <path>.sig sidecar (produced by ssf sign) must exist; the
upload uses it as the signature payload.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLog(args[0], instance)
		},
	}
	cmd.Flags().StringVar(&instance, "instance", "public", "rekor instance (public | <https URL>)")
	return cmd
}

func runLog(path, instance string) error {
	bin, err := artifact.NewBinary(path)
	if err != nil {
		return err
	}

	rekor, err := resolveTool("rekor-cli", "https://docs.sigstore.dev/logging/installation")
	if err != nil {
		return err
	}

	server := instance
	if instance == "" || instance == "public" {
		server = "https://rekor.sigstore.dev"
	}

	args := []string{
		"upload",
		"--rekor_server", server,
		"--artifact", bin.Reference(),
		"--signature", bin.SignaturePath(),
		"--type", "hashedrekord",
	}

	if err := runTool(rekor, args...); err != nil {
		return fmt.Errorf("rekor-cli: %w", err)
	}

	fmt.Printf("logged %s\n", bin.Reference())
	fmt.Printf("  rekor:     %s\n", server)
	fmt.Printf("  digest:    %s\n", bin.Digest())
	fmt.Printf("  signature: %s\n", bin.SignaturePath())
	return nil
}
