package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// notImplemented is the shared run handler for every Phase 2.4a stub.
//
// Returning an error (rather than printing and returning nil) sets a non-zero
// exit code so callers — CI, the eventual MCP wrapper — see a real failure
// instead of believing the operation succeeded.
func notImplemented(phase string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf(
			"%s: not yet implemented (lands in NEB-PLAN-phasing %s)",
			cmd.CommandPath(),
			phase,
		)
	}
}
