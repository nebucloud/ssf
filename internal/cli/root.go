// Package cli wires the cobra command tree for the `ssf` binary.
//
// Commands are split one-per-file so each subcommand's flags, validation, and
// help text live close together. NewRootCommand assembles the tree and is the
// only exported symbol — the binary entrypoint in cmd/ssf/main.go calls it.
package cli

import "github.com/spf13/cobra"

// NewRootCommand builds the `ssf` cobra command tree.
//
// In Phase 2.4a every subcommand is a stub that prints "not yet implemented"
// when invoked — the goal of 2.4a is that `ssf --help` lists the entire
// surface so reviewers can validate the CLI shape against SSF-ARCH-overview §5.
// Real handlers land in 2.4b (sign/verify), 2.4c (run), and 2.4d (policy).
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "ssf",
		Short: "NebuCloud Secure Software Factory — sign, attest, and verify supply chain artifacts",
		Long: `ssf is the NebuCloud Secure Software Factory CLI.

It applies supply-chain operations (sign, verify, attest, sbom, log, policy)
to any artifact type — container images, binaries, Rust crates, npm packages,
World Builder derivations, or arbitrary blobs — and orchestrates pipelines
declared in ssf.yaml by emitting a kiln pipeline manifest and invoking
` + "`kiln run`" + `.

See https://github.com/nebucloud/docs/blob/main/SSF-ARCH-overview.md for the
full architecture, and SSF-SPEC-ssf-yaml for the pipeline definition spec.`,
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	root.AddCommand(
		newSignCommand(),
		newVerifyCommand(),
		newAttestCommand(),
		newSBOMCommand(),
		newLogCommand(),
		newPolicyCommand(),
		newRunCommand(),
		newInitCommand(),
	)

	return root
}
