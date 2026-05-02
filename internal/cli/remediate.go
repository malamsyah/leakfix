package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/malamsyah/leakfix/internal/agent"
	"github.com/malamsyah/leakfix/internal/git"
	"github.com/malamsyah/leakfix/internal/githubclient"
	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/render"
	"github.com/malamsyah/leakfix/internal/report"
	"github.com/malamsyah/leakfix/internal/runbooks"
	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/spf13/cobra"
)

func newRemediateCmd() *cobra.Command {
	var (
		apply               bool
		rewriteHistory      bool
		providers           []string
		confidence          string
		baseBranch          string
		noIssue             bool
		outputPath          string
		includeTestFiles    bool
		includeDummySecrets bool
		noFilter            bool
	)

	cmd := &cobra.Command{
		Use:   "remediate <repo-path>",
		Short: "Generate a remediation plan; with --apply, open a PR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			repoPath := args[0]

			reg, err := runbooks.Load()
			if err != nil {
				return fmt.Errorf("load runbooks: %w", err)
			}

			s := scanner.New()
			findings, meta, err := s.Scan(ctx, repoPath, scanner.Options{Confidence: confidence})
			if err != nil {
				return fmt.Errorf("scan: %w", err)
			}

			fopts := scanner.FilterOptions{
				IncludeTestFiles:    includeTestFiles || noFilter,
				IncludeDummySecrets: includeDummySecrets || noFilter,
			}
			fres := scanner.ApplyFilters(findings, fopts)
			findings = fres.Kept
			if fres.DroppedVendored > 0 || fres.DroppedTestPath > 0 || fres.DroppedDummyValue > 0 {
				fmt.Fprintf(os.Stderr, "filtered: %d vendored, %d test paths, %d dummy/placeholder values (use --no-filter for test/dummy; vendored is always skipped)\n",
					fres.DroppedVendored, fres.DroppedTestPath, fres.DroppedDummyValue)
			}

			findings = filterByProviders(findings, providers, reg)

			client, err := agent.DefaultClient()
			if err != nil {
				return err
			}
			ag := agent.New(client, reg, repoPath)

			pln := &plan.Plan{
				RepoPath:      repoPath,
				BaseBranch:    baseBranch,
				GeneratedAt:   time.Now().UTC(),
				KingfisherVer: meta.KingfisherVersion,
				LeakfixVer:    buildVersion,
			}
			items, err := ag.PlanForFindings(ctx, findings)
			if err != nil {
				return fmt.Errorf("plan: %w", err)
			}
			pln.Items = items

			if rewriteHistory {
				pln.HistoryRewrite = buildHistoryRewrite(findings)
			}

			if err := pln.Validate(); err != nil {
				return fmt.Errorf("plan validate: %w", err)
			}

			secrets := scanner.SecretValues(findings)
			redactedPlan, err := pln.Redact(secrets)
			if err != nil {
				return fmt.Errorf("plan redact: %w", err)
			}

			if !apply {
				out, closer, err := openOutput(outputPath, os.Stdout)
				if err != nil {
					return err
				}
				defer closer()
				if err := render.Plan(out, redactedPlan); err != nil {
					return err
				}
				return nil
			}

			// --apply path
			if err := git.RefuseDirty(repoPath); err != nil {
				return err
			}

			gh, err := githubclient.New(ctx)
			if err != nil {
				return fmt.Errorf("github client: %w", err)
			}

			outcome, err := executeApply(ctx, executeArgs{
				Repo:           repoPath,
				Plan:           pln,
				Redacted:       redactedPlan,
				Findings:       findings,
				BaseBranch:     baseBranch,
				CreateIssue:    !noIssue,
				RewriteHistory: rewriteHistory,
				Github:         gh,
			})
			if err != nil {
				return err
			}

			out, closer, err := openOutput(outputPath, os.Stdout)
			if err != nil {
				return err
			}
			defer closer()
			return report.Write(out, &report.Context{
				Plan:       redactedPlan,
				PRURL:      outcome.PRURL,
				IssueURL:   outcome.IssueURL,
				BranchName: outcome.BranchName,
				Failures:   outcome.Failures,
			})
		},
	}

	cmd.Flags().BoolVar(&apply, "apply", false, "create branch, commits, PR, and tracking issue (default: dry run)")
	cmd.Flags().BoolVar(&rewriteHistory, "rewrite-history", false, "additionally emit git-filter-repo plan + warnings")
	cmd.Flags().StringSliceVar(&providers, "providers", nil, "comma-separated provider IDs to limit remediation to")
	cmd.Flags().StringVar(&confidence, "confidence", "medium", "kingfisher confidence threshold: low|medium|high")
	cmd.Flags().StringVar(&baseBranch, "base-branch", "", "base branch for the PR (default: repo default branch)")
	cmd.Flags().BoolVar(&noIssue, "no-issue", false, "skip tracking issue creation")
	cmd.Flags().StringVar(&outputPath, "output", "", "also write plan/report to file")
	cmd.Flags().BoolVar(&includeTestFiles, "include-test-files", false, "include findings in obvious test paths (testdata/, _test.go, fixtures/, ...)")
	cmd.Flags().BoolVar(&includeDummySecrets, "include-dummy-secrets", false, "include findings whose value contains EXAMPLE/DUMMY/FAKE/PLACEHOLDER markers")
	cmd.Flags().BoolVar(&noFilter, "no-filter", false, "shorthand for --include-test-files --include-dummy-secrets")
	return cmd
}

func openOutput(path string, fallback io.Writer) (io.Writer, func(), error) {
	if path == "" {
		return fallback, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

func filterByProviders(findings []scanner.Finding, providers []string, reg *runbooks.Registry) []scanner.Finding {
	if len(providers) == 0 {
		return findings
	}
	allowed := map[string]bool{}
	for _, p := range providers {
		allowed[strings.TrimSpace(p)] = true
	}
	out := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		rb, _ := reg.Match(f.RuleID)
		if allowed[rb.ID] {
			out = append(out, f)
		}
	}
	return out
}

func buildHistoryRewrite(findings []scanner.Finding) *plan.HistoryRewrite {
	files := map[string]struct{}{}
	for _, f := range findings {
		for _, loc := range f.Locations {
			files[loc.File] = struct{}{}
		}
	}
	if len(files) == 0 {
		return nil
	}
	args := []string{"git filter-repo"}
	for file := range files {
		args = append(args, fmt.Sprintf("--path %s --invert-paths", file))
	}
	cmd := strings.Join(args, " \\\n  ")
	return &plan.HistoryRewrite{
		Command: cmd,
		SideEffects: []string{
			"All commit SHAs change",
			"GPG/SSH commit signatures are dropped",
			"Open PR diffs are invalidated",
			"All collaborators must re-clone or hard-reset",
		},
		PostSteps: []string{
			"Verify the rewrite locally with `git log --all --oneline`",
			"Coordinate a freeze window with all contributors",
			"Force-push: `git push --force --all && git push --force --tags`",
			"Notify collaborators to re-clone the repository",
		},
	}
}

// executeArgs and executeApply live in apply.go; declared via interface below for testability.
var ErrApplyAborted = errors.New("apply aborted")
