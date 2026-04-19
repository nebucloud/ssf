package cli

import "github.com/spf13/cobra"

func newAttestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest <artifact>",
		Short: "Attach an in-toto attestation predicate to an artifact",
		Long: `Generate or attach an in-toto attestation predicate to an artifact.

Predicates supported:
  - slsa-provenance: auto-generated from build metadata
  - sbom:            references an existing SBOM file via --source
  - custom:          attach a user-provided predicate JSON via --source

Cosign signs the in-toto statement and stores it as a sibling .att artifact
(OCI) or as <path>.att file (binary, crate, npm, blob).`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4c"),
	}
	cmd.Flags().String("predicate", "slsa-provenance", "predicate type (slsa-provenance | sbom | custom)")
	cmd.Flags().String("source", "", "input file for sbom/custom predicates (path)")
	return cmd
}
