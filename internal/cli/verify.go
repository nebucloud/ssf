package cli

import (
	"fmt"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/spf13/cobra"
)

func newVerifyCommand() *cobra.Command {
	var keyRef string

	cmd := &cobra.Command{
		Use:   "verify <artifact>",
		Short: "Verify an artifact signature with cosign",
		Long: `Verify an artifact signature using cosign verify-blob.

Mirrors the sign dispatch — Phase 2.4b only wires the binary type, which
shells to ` + "`cosign verify-blob`" + ` against the conventionally-located
<path>.sig sidecar.

Without --key, cosign uses the same default key discovery as ` + "`ssf sign`" + `.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0], keyRef)
		},
	}
	cmd.Flags().StringVar(&keyRef, "key", "", "verification key reference (cosign | vault://path | fulcio | file://path)")
	return cmd
}

func runVerify(path, keyRef string) error {
	bin, err := artifact.NewBinary(path)
	if err != nil {
		return err
	}

	cosignKey, err := translateKey(keyRef)
	if err != nil {
		return err
	}
	if cosignKey == "" {
		// cosign verify-blob requires --key for keyed signatures; if the
		// user didn't supply one and we can't derive a default, fail
		// fast with a clear hint instead of cosign's generic error.
		return fmt.Errorf("verify requires --key (e.g., --key cosign.pub or --key file:///path/to/cosign.pub)")
	}

	args := []string{
		"verify-blob",
		"--key", cosignKey,
		"--signature", bin.SignaturePath(),
		bin.Reference(),
	}

	if err := runCosign(args...); err != nil {
		return err
	}

	fmt.Printf("verified %s\n", bin.Reference())
	fmt.Printf("  digest:    %s\n", bin.Digest())
	fmt.Printf("  signature: %s\n", bin.SignaturePath())
	return nil
}
