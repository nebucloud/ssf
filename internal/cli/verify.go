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
		Long: `Verify an artifact signature using cosign.

Dispatch:
  • existing file path → cosign verify-blob against <path>.sigstore.json
  • registry reference → cosign verify against the OCI signature sibling

Without --key, cosign uses the same default key discovery as ` + "`ssf sign`" + `.
Keyed blob verification requires an explicit --key.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0], keyRef)
		},
	}
	cmd.Flags().StringVar(&keyRef, "key", "", "verification key reference (cosign | vault://path | fulcio | file://path)")
	return cmd
}

func runVerify(ref, keyRef string) error {
	art, err := artifact.Open(ref)
	if err != nil {
		return err
	}

	cosignKey, err := translateKey(keyRef)
	if err != nil {
		return err
	}

	switch a := art.(type) {
	case *artifact.Binary:
		if cosignKey == "" {
			return fmt.Errorf("verify requires --key (e.g., --key cosign.pub or --key file:///path/to/cosign.pub)")
		}
		args := []string{
			"verify-blob",
			"--key", cosignKey,
			"--bundle", a.BundlePath(),
			"--insecure-ignore-tlog",
			a.Reference(),
		}
		if err := runCosign(args...); err != nil {
			return err
		}
		fmt.Printf("verified %s\n", a.Reference())
		fmt.Printf("  type:      %s\n", a.Type())
		fmt.Printf("  digest:    %s\n", a.Digest())
		fmt.Printf("  bundle:    %s\n", a.BundlePath())
		return nil

	case *artifact.OCI:
		if cosignKey == "" {
			return fmt.Errorf("verify requires --key (e.g., --key cosign.pub or --key file:///path/to/cosign.pub)")
		}
		args := []string{"verify", "--key", cosignKey, a.DigestRef()}
		if err := runCosign(args...); err != nil {
			return err
		}
		fmt.Printf("verified %s\n", a.Reference())
		fmt.Printf("  type:      %s\n", a.Type())
		fmt.Printf("  digest:    %s\n", a.Digest())
		fmt.Printf("  digestRef: %s\n", a.DigestRef())
		return nil

	default:
		return fmt.Errorf("verify: unsupported artifact type %s", art.Type())
	}
}
