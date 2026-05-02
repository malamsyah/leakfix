package cli

import (
	"bytes"
	"context"
	"fmt"

	"github.com/malamsyah/leakfix/internal/git"
	"github.com/malamsyah/leakfix/internal/githubclient"
	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/render"
	"github.com/malamsyah/leakfix/internal/report"
	"github.com/malamsyah/leakfix/internal/scanner"
)

type executeArgs struct {
	Repo           string
	Plan           *plan.Plan // pre-redaction (used to apply edits)
	Redacted       *plan.Plan // post-redaction (used for rendering)
	Findings       []scanner.Finding
	BaseBranch     string
	CreateIssue    bool
	RewriteHistory bool
	Github         *githubclient.Client
}

type applyOutcome struct {
	PRURL      string
	IssueURL   string
	BranchName string
	Failures   []report.ExecutionFailure
}

func executeApply(ctx context.Context, a executeArgs) (*applyOutcome, error) {
	owner, repo, err := git.RemoteOwnerRepo(a.Repo)
	if err != nil {
		return nil, fmt.Errorf("derive remote: %w", err)
	}

	branchName := git.BranchName(a.Plan)

	// Idempotency check: branch already exists?
	branchExists, _ := git.BranchExists(ctx, a.Repo, branchName)
	if branchExists {
		prNumber, prURL, _ := a.Github.FindOpenPRForBranch(ctx, owner, repo, branchName)
		if prNumber > 0 {
			return &applyOutcome{
				PRURL:      prURL,
				BranchName: branchName,
			}, fmt.Errorf("PR #%d already open for this set of findings; close it or delete the branch to retry", prNumber)
		}
		return nil, fmt.Errorf("branch %s already exists locally/remotely but no open PR found; delete it before re-running", branchName)
	}

	if err := git.CheckoutNewBranch(a.Repo, branchName, a.BaseBranch); err != nil {
		return nil, fmt.Errorf("checkout branch: %w", err)
	}

	failures, err := git.ApplyPlanEdits(a.Repo, a.Plan)
	if err != nil {
		return nil, fmt.Errorf("apply edits: %w", err)
	}

	commitMessage := git.BuildCommitMessage(a.Redacted, 0)
	commitMessage = git.RedactString(commitMessage, scanner.SecretValues(a.Findings))
	if err := git.CommitAll(a.Repo, commitMessage); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	if err := git.PushBranch(ctx, a.Repo, branchName); err != nil {
		return nil, fmt.Errorf("push: %w", err)
	}

	var (
		issueNumber int
		issueURL    string
		prNumber    int
		prURL       string
	)

	if a.CreateIssue {
		// Render with PRNumber=0 first; we update after PR is created.
		var buf bytes.Buffer
		if err := render.IssueBody(&buf, &render.IssueRenderContext{Plan: a.Redacted, PRNumber: 0}); err != nil {
			return nil, fmt.Errorf("render issue: %w", err)
		}
		issueNumber, issueURL, err = a.Github.OpenIssue(ctx, owner, repo, "Secret leak remediation tracker", buf.String())
		if err != nil {
			return nil, fmt.Errorf("open issue: %w", err)
		}
	}

	var prBody bytes.Buffer
	if err := render.PRBody(&prBody, &render.PRRenderContext{Plan: a.Redacted, IssueNumber: issueNumber}); err != nil {
		return nil, fmt.Errorf("render pr: %w", err)
	}

	defaultBase := a.BaseBranch
	if defaultBase == "" {
		defaultBase, _ = a.Github.DefaultBranch(ctx, owner, repo)
		if defaultBase == "" {
			defaultBase = "main"
		}
	}
	prNumber, prURL, err = a.Github.OpenPR(ctx, owner, repo, githubclient.OpenPROptions{
		Title: "Replace leaked secrets with environment variable references",
		Body:  prBody.String(),
		Head:  branchName,
		Base:  defaultBase,
	})
	if err != nil {
		return nil, fmt.Errorf("open pr: %w", err)
	}

	if a.CreateIssue && issueNumber > 0 {
		var buf bytes.Buffer
		if err := render.IssueBody(&buf, &render.IssueRenderContext{Plan: a.Redacted, PRNumber: prNumber}); err == nil {
			_ = a.Github.UpdateIssueBody(ctx, owner, repo, issueNumber, buf.String())
		}
	}

	out := &applyOutcome{
		PRURL:      prURL,
		IssueURL:   issueURL,
		BranchName: branchName,
		Failures:   convertFailures(failures),
	}
	return out, nil
}

func convertFailures(in []git.EditFailure) []report.ExecutionFailure {
	out := make([]report.ExecutionFailure, len(in))
	for i, f := range in {
		out[i] = report.ExecutionFailure{
			File:   f.File,
			Reason: f.Reason,
		}
	}
	return out
}
