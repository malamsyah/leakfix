package report

import (
	"io"

	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/render"
)

// ExecutionFailure is a single CodeEdit that failed to apply at Stage 5.
type ExecutionFailure struct {
	File   string
	Reason string
}

// Context holds everything needed to render the post-execute report.
type Context struct {
	Plan       *plan.Plan
	PRURL      string
	IssueURL   string
	BranchName string
	Failures   []ExecutionFailure
}

// Write renders the final report markdown.
func Write(w io.Writer, ctx *Context) error {
	failures := make([]render.ExecutionFailure, len(ctx.Failures))
	for i, f := range ctx.Failures {
		failures[i] = render.ExecutionFailure{File: f.File, Reason: f.Reason}
	}
	return render.Report(w, &render.ReportRenderContext{
		Plan:       ctx.Plan,
		PRURL:      ctx.PRURL,
		IssueURL:   ctx.IssueURL,
		BranchName: ctx.BranchName,
		Failures:   failures,
	})
}
