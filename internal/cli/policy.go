package cli

import "github.com/spf13/cobra"

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Evaluate, list, validate, or explain CUE supply-chain policies",
	}
	cmd.AddCommand(
		newPolicyCheckCommand(),
		newPolicyListCommand(),
		newPolicyValidateCommand(),
		newPolicyExplainCommand(),
		newPolicySchemaCommand(),
	)
	return cmd
}

func newPolicyCheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check <artifact>",
		Short: "Evaluate one or more CUE policies against an artifact",
		Long: `Evaluate CUE policies against an artifact and report pass/fail per policy.

The artifact's current signed/attested/sbom state is loaded into a CUE value,
then unified with each --policy file. CUE's unification (set intersection)
gives ordered-independent composition; failures surface with a path-and-reason
suitable for both humans and JSON consumers.

See SSF-SPEC-policies for the full schema and authoring guide.`,
		Args: cobra.ExactArgs(1),
		RunE: notImplemented("2.4d"),
	}
	cmd.Flags().StringArrayP("policy", "p", nil, "policy file path (repeatable)")
	cmd.Flags().Bool("all", false, "include all built-in policies")
	cmd.Flags().Bool("strict", false, "shortcut for --built-in strict")
	cmd.Flags().String("built-in", "", "named built-in policy (strict | recent-scan | …)")
	cmd.Flags().Bool("json", false, "emit JSON output for tooling")
	cmd.Flags().Bool("fail-open", false, "log failures but exit 0 (overrides ssf.yaml)")
	cmd.Flags().String("artifact-file", "", "path to a pre-constructed artifact JSON (testing)")
	return cmd
}

func newPolicyListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List built-in policies shipped with this ssf release",
		RunE:  notImplemented("2.4d"),
	}
}

func newPolicyValidateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <policy.cue>",
		Short: "Validate a policy file for syntax errors without running it",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented("2.4d"),
	}
}

func newPolicyExplainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <policy.cue>",
		Short: "Walk a policy and describe what it enforces (no artifact required)",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented("2.4d"),
	}
}

func newPolicySchemaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Print the effective #Artifact schema policies are evaluated against",
		RunE:  notImplemented("2.4d"),
	}
}
