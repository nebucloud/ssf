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
		Long: `Sign an artifact with cosign.

Dispatch:
  • existing file path → cosign sign-blob → <path>.sigstore.json (binary)
  • registry reference → cosign sign against the manifest digest (oci)

Without --key, cosign uses its default key discovery (COSIGN_PASSWORD env,
~/.config/sigstore/cosign.key, KMS, or interactive prompt).

OCI images must be reachable in a registry (digest resolved via crane or
docker). Local-only images need a push first.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSign(args[0], keyRef)
		},
	}
	cmd.Flags().StringVar(&keyRef, "key", "", "signing key reference (cosign | vault://path | fulcio | file://path)")
	return cmd
}

func runSign(ref, keyRef string) error {
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
		args := []string{"sign-blob", "--yes", "--bundle", a.BundlePath()}
		if cosignKey != "" {
			args = append(args, "--key", cosignKey)
		}
		args = append(args, a.Reference())
		if err := runCosign(args...); err != nil {
			return err
		}
		fmt.Printf("signed %s\n", a.Reference())
		fmt.Printf("  type:      %s\n", a.Type())
		fmt.Printf("  digest:    %s\n", a.Digest())
		fmt.Printf("  bundle:    %s\n", a.BundlePath())
		return nil

	case *artifact.OCI:
		args := []string{"sign", "--yes"}
		if cosignKey != "" {
			args = append(args, "--key", cosignKey)
		}
		args = append(args, a.DigestRef())
		if err := runCosign(args...); err != nil {
			return err
		}
		fmt.Printf("signed %s\n", a.Reference())
		fmt.Printf("  type:      %s\n", a.Type())
		fmt.Printf("  digest:    %s\n", a.Digest())
		fmt.Printf("  digestRef: %s\n", a.DigestRef())
		return nil

	default:
		return fmt.Errorf("sign: unsupported artifact type %s", art.Type())
	}
}
