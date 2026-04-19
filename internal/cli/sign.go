package cli

import (
	"fmt"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/spf13/cobra"
)

func newSignCommand() *cobra.Command {
	var keyRef string

	cmd := &cobra.Command{
		Use:   "sign <artifact>",
		Short: "Sign an artifact with cosign",
		Long: `Sign an artifact with cosign and store the signature alongside it.

In Phase 2.4b only the binary artifact type is wired — ssf shells to
` + "`cosign sign-blob`" + ` and writes the signature to <path>.sig. Other types
(oci, crate, npm, derivation, blob) land alongside their dispatch in
later phases.

Without --key, cosign uses its default key discovery (COSIGN_PASSWORD env,
~/.config/sigstore/cosign.key, KMS, or interactive prompt).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(args[0], keyRef)
		},
	}
	cmd.Flags().StringVar(&keyRef, "key", "", "signing key reference (cosign | vault://path | fulcio | file://path)")
	return cmd
}

func runSign(path, keyRef string) error {
	bin, err := artifact.NewBinary(path)
	if err != nil {
		return err
	}

	cosignKey, err := translateKey(keyRef)
	if err != nil {
		return err
	}

	args := []string{"sign-blob", "--yes", "--output-signature", bin.SignaturePath()}
	if cosignKey != "" {
		args = append(args, "--key", cosignKey)
	}
	args = append(args, bin.Reference())

	if err := runCosign(args...); err != nil {
		return err
	}

	// Surface the artifact's content digest and the resulting signature
	// path on stdout so the caller can pipe to a follow-up step (verify,
	// upload, attest) without reparsing the file system.
	fmt.Printf("signed %s\n", bin.Reference())
	fmt.Printf("  digest:    %s\n", bin.Digest())
	fmt.Printf("  signature: %s\n", bin.SignaturePath())
	return nil
}
