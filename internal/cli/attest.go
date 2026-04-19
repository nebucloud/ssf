package cli

import (
	"fmt"

	"github.com/nebucloud/ssf/pkg/artifact"
	"github.com/spf13/cobra"
)

func newAttestCommand() *cobra.Command {
	var (
		predicate string
		source    string
		keyRef    string
	)

	cmd := &cobra.Command{
		Use:   "attest <artifact>",
		Short: "Attach an in-toto attestation predicate to an artifact",
		Long: `Generate or attach an in-toto attestation predicate using cosign attest-blob.

Supported predicate types in 2.4c.2:
  - sbom:    references an existing SBOM file via --source (spdxjson)
  - custom:  attaches a user-provided predicate JSON via --source

slsa-provenance auto-generation lands alongside kiln materials wiring in
a future phase.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttest(args[0], predicate, source, keyRef)
		},
	}
	cmd.Flags().StringVar(&predicate, "predicate", "", "predicate type (sbom | custom)")
	cmd.Flags().StringVar(&source, "source", "", "input file for the predicate (path)")
	cmd.Flags().StringVar(&keyRef, "key", "", "signing key reference (cosign | vault://path | file://path)")
	return cmd
}

func runAttest(path, predicate, source, keyRef string) error {
	if predicate == "" {
		return fmt.Errorf("--predicate is required (sbom | custom)")
	}
	if predicate == "slsa-provenance" {
		return fmt.Errorf("--predicate slsa-provenance is not yet supported (lands when kiln materials wiring ships)")
	}
	if predicate != "sbom" && predicate != "custom" {
		return fmt.Errorf("--predicate %q must be sbom or custom", predicate)
	}
	if source == "" {
		return fmt.Errorf("--source is required for predicate %q", predicate)
	}

	bin, err := artifact.NewBinary(path)
	if err != nil {
		return err
	}

	cosignKey, err := translateKey(keyRef)
	if err != nil {
		return err
	}

	cosignType := "spdxjson"
	if predicate == "custom" {
		cosignType = "custom"
	}

	args := []string{
		"attest-blob",
		"--yes",
		"--predicate", source,
		"--type", cosignType,
	}
	if cosignKey != "" {
		args = append(args, "--key", cosignKey)
	}
	args = append(args, bin.Reference())

	if err := runCosign(args...); err != nil {
		return err
	}

	fmt.Printf("attested %s\n", bin.Reference())
	fmt.Printf("  digest:    %s\n", bin.Digest())
	fmt.Printf("  predicate: %s (%s)\n", predicate, source)
	return nil
}
