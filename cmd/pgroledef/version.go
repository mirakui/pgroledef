package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Injected via -ldflags at release build time; see .goreleaser.yaml.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// versionLine is what both "pgroledef version" and "pgroledef --version" print.
func versionLine() string {
	return fmt.Sprintf("pgroledef %s (%s, %s)", version, commit, date)
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit and build date of this binary",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), versionLine())
			return nil
		},
	}
}
