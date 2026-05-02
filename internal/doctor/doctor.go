package doctor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/malamsyah/leakfix/internal/scanner"
)

// DefaultTimeout for the full doctor run.
const DefaultTimeout = 30 * time.Second

// Check is the result of a single preflight check.
type Check struct {
	Name           string `json:"name"`
	OK             bool   `json:"ok"`
	Version        string `json:"version,omitempty"`
	SupportedRange string `json:"supported_range,omitempty"`
	Error          string `json:"error,omitempty"`
	Remediation    string `json:"remediation,omitempty"`
	humanLabel     string
	humanFooter    string
}

// Report is the full doctor output.
type Report struct {
	OK     bool    `json:"ok"`
	Checks []Check `json:"checks"`
}

// Run executes every check and returns the populated Report.
func Run(ctx context.Context) Report {
	checks := []Check{
		checkKingfisher(ctx),
		checkBinary(ctx, "git-filter-repo", "git-filter-repo", []string{"--version"}, ">=2.40.0", "install with: pip install git-filter-repo"),
		checkGH(ctx),
		checkAnthropicKey(),
		checkGoVersion(),
	}
	rep := Report{OK: true, Checks: checks}
	for _, c := range checks {
		if !c.OK {
			rep.OK = false
		}
	}
	return rep
}

// WriteHuman renders the report in a friendly human format.
func (r *Report) WriteHuman(w io.Writer) {
	for _, c := range r.Checks {
		marker := "✓"
		if !c.OK {
			marker = "✗"
		}
		label := c.humanLabel
		if label == "" {
			label = c.Name
		}
		left := fmt.Sprintf("%s %s", marker, label)
		right := c.Version
		if right == "" {
			right = c.Error
		}
		footer := c.humanFooter
		if footer == "" && c.SupportedRange != "" {
			footer = fmt.Sprintf("(%s supported)", c.SupportedRange)
		}
		if footer == "" && !c.OK {
			footer = c.Remediation
		}
		fmt.Fprintf(w, "%-30s %s %s\n", left, right, footer)
	}
	fmt.Fprintln(w)
	if r.OK {
		fmt.Fprintln(w, "All checks passed.")
	} else {
		fmt.Fprintln(w, "Some checks failed.")
	}
}

// checkKingfisher checks that kingfisher is on PATH AND that its version is
// inside the supported semver range. SPEC §17.2: out-of-range warns rather
// than errors — but doctor surfaces it so the user knows.
func checkKingfisher(ctx context.Context) Check {
	supportedRange := fmt.Sprintf(">=%s, <%s", scanner.MinSupportedKingfisher, scanner.MaxSupportedKingfisher)
	c := Check{
		Name:           "kingfisher",
		humanLabel:     "Kingfisher",
		SupportedRange: supportedRange,
		Remediation:    "install: brew install kingfisher (or see https://github.com/mongodb/kingfisher#installation)",
	}
	path, err := exec.LookPath("kingfisher")
	if err != nil {
		c.OK = false
		c.Error = "not found on PATH"
		return c
	}
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		c.OK = false
		c.Error = fmt.Sprintf("could not invoke kingfisher --version: %v", err)
		return c
	}
	c.Version = firstLine(string(out))
	inRange, _ := scanner.CheckKingfisherVersion(c.Version)
	if !inRange {
		c.OK = false
		c.Error = fmt.Sprintf("version %s is outside the supported range %s", c.Version, supportedRange)
		c.Remediation = "leakfix may still work; the JSON parser is non-strict. Open an issue if you hit a parse error."
		return c
	}
	c.OK = true
	return c
}

func checkBinary(ctx context.Context, bin, label string, versionArgs []string, supported, remediation string) Check {
	c := Check{Name: bin, humanLabel: label, SupportedRange: supported, Remediation: remediation}
	path, err := exec.LookPath(bin)
	if err != nil {
		c.OK = false
		c.Error = "not found on PATH"
		return c
	}
	out, err := exec.CommandContext(ctx, path, versionArgs...).Output()
	if err != nil {
		c.OK = false
		c.Error = fmt.Sprintf("could not invoke %s --version: %v", bin, err)
		return c
	}
	c.Version = firstLine(string(out))
	c.OK = true
	return c
}

func checkGH(ctx context.Context) Check {
	c := Check{Name: "gh_or_gh_token", humanLabel: "gh CLI / GH_TOKEN"}
	if v := os.Getenv("GH_TOKEN"); v != "" {
		c.OK = true
		c.Version = "GH_TOKEN env var present"
		return c
	}
	path, err := exec.LookPath("gh")
	if err != nil {
		c.OK = false
		c.Error = "neither gh CLI nor GH_TOKEN found"
		c.Remediation = "install gh CLI (https://cli.github.com) or set GH_TOKEN"
		return c
	}
	out, err := exec.CommandContext(ctx, path, "--version").Output()
	if err != nil {
		c.OK = false
		c.Error = fmt.Sprintf("gh --version failed: %v", err)
		return c
	}
	c.Version = firstLine(string(out))
	statusOut, _ := exec.CommandContext(ctx, path, "auth", "status").CombinedOutput()
	c.humanFooter = firstLine(string(statusOut))
	c.OK = true
	return c
}

func checkAnthropicKey() Check {
	c := Check{Name: "anthropic_api_key", humanLabel: "ANTHROPIC_API_KEY"}
	v := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	if v == "" {
		c.OK = false
		c.Error = "not set"
		c.Remediation = "export ANTHROPIC_API_KEY=sk-ant-..."
		return c
	}
	c.OK = true
	c.Version = "set (" + maskKey(v) + ")"
	return c
}

func maskKey(s string) string {
	if len(s) <= 7 {
		return "***"
	}
	return s[:7] + "...." + s[len(s)-4:]
}

func checkGoVersion() Check {
	c := Check{Name: "go", humanLabel: "Go", SupportedRange: ">=1.22"}
	c.Version = strings.TrimPrefix(runtime.Version(), "go")
	c.OK = true
	return c
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
