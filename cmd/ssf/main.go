// Command ssf is the NebuCloud Secure Software Factory CLI.
//
// Thin entrypoint — all command construction and dispatch lives in
// [github.com/nebucloud/ssf/internal/cli]. Keeping main.go free of logic makes
// the binary easy to retarget (e.g., embed into a TUI, wrap in a long-running
// daemon, or expose via the future SSF MCP server) without rewriting the
// command tree.
package main

import (
	"fmt"
	"os"

	"github.com/nebucloud/ssf/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "ssf:", err)
		os.Exit(1)
	}
}
