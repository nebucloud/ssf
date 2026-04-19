package cli

import "github.com/spf13/cobra"

func newRunCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "run <ssf.yaml>",
		Short: "Execute the supply-chain pipeline declared in an ssf.yaml file",
		Long: `Parse ssf.yaml, emit a kiln pipeline manifest (JSON), and invoke kiln to
execute it hermetically.

Per KLN-D-02, ssf emits the manifest as JSON conforming to kiln's Pipeline
type — kiln then handles toposort, parallel wave extraction, sandbox
isolation, and content-addressed caching. Tools (cosign, syft, cue,
rekor-cli) must be on PATH for v1; World Builder–provided tool versions
land in a future phase.

With --dry-run, ssf prints the generated manifest without invoking kiln —
useful for debugging or pre-flighting CI changes.`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4c"),
	}
	cmd.Flags().Bool("dry-run", false, "print the generated kiln manifest without executing")
	return cmd
}
