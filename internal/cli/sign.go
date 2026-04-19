package cli

import "github.com/spf13/cobra"

func newSignCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <artifact>",
		Short: "Sign an artifact with cosign",
		Long: `Sign an artifact with cosign and store the signature alongside it.

The signature mechanism is type-dependent:
  - oci:    cosign sign — signature pushed as a sibling OCI artifact
  - binary: cosign sign-blob — signature written next to the file as <path>.sig
  - crate:  cosign sign-blob against the .crate tarball
  - npm:    cosign sign-blob against the package tarball
  - other:  cosign sign-blob

Without --key, ssf uses Cosign's default key discovery (env, KMS, file).`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4b"),
	}
	cmd.Flags().String("key", "", "signing key reference (cosign | vault://path | fulcio | file://path)")
	return cmd
}
