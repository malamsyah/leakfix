package cli

import (
	"github.com/spf13/cobra"
)

var (
	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// BuildInfo returns the recorded version/commit/date metadata.
func BuildInfo() (version, commit, date string) {
	return buildVersion, buildCommit, buildDate
}

// SetBuildInfo records build-time metadata. Called from main.
func SetBuildInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
}

// Version returns the current build version string.
func Version() string { return buildVersion }

type globalFlags struct {
	verbose bool
	quiet   bool
	noColor bool
}

var globals globalFlags

// Root constructs the cobra root command and registers subcommands.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "leakfix",
		Short:         "Remediation agent for Kingfisher findings",
		Long:          "leakfix generates per-provider revocation runbooks, opens review-ready PRs, and (optionally) emits git history-rewrite plans.",
		Version:       buildVersion,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVarP(&globals.verbose, "verbose", "v", false, "increase log verbosity (debug)")
	root.PersistentFlags().BoolVarP(&globals.quiet, "quiet", "q", false, "suppress non-error output")
	root.PersistentFlags().BoolVar(&globals.noColor, "no-color", false, "disable ANSI color")

	root.AddCommand(newDoctorCmd())
	root.AddCommand(newRunbookCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newScanOrgCmd())
	root.AddCommand(newRemediateCmd())

	return root
}
