package main

import (
	"fmt"
	"os"

	"github.com/malamsyah/leakfix/internal/cli"
)

// Set at build time via -ldflags "-X main.version=..."
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetBuildInfo(version, commit, date)
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
