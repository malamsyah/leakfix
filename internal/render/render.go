package render

import (
	"embed"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/malamsyah/leakfix/internal/plan"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// PRRenderContext is the data passed to pr_body.md.tmpl. The Plan is
// post-redaction; IssueNumber is filled in once the issue exists.
type PRRenderContext struct {
	Plan        *plan.Plan
	IssueNumber int
}

// IssueRenderContext is the data passed to issue_body.md.tmpl.
type IssueRenderContext struct {
	Plan     *plan.Plan
	PRNumber int
}

// ReportRenderContext is the data passed to report.md.tmpl.
type ReportRenderContext struct {
	Plan       *plan.Plan
	PRURL      string
	IssueURL   string
	BranchName string
	Failures   []ExecutionFailure
}

// ExecutionFailure mirrors report.ExecutionFailure to keep render free of
// circular imports.
type ExecutionFailure struct {
	File   string
	Reason string
}

// Plan renders the dry-run plan markdown.
func Plan(w io.Writer, p *plan.Plan) error {
	t, err := loadTemplate("plan.md.tmpl")
	if err != nil {
		return err
	}
	return t.Execute(w, p)
}

// PRBody renders the pull request body markdown.
func PRBody(w io.Writer, ctx *PRRenderContext) error {
	t, err := loadTemplate("pr_body.md.tmpl")
	if err != nil {
		return err
	}
	return t.Execute(w, ctx)
}

// IssueBody renders the tracking-issue body markdown.
func IssueBody(w io.Writer, ctx *IssueRenderContext) error {
	t, err := loadTemplate("issue_body.md.tmpl")
	if err != nil {
		return err
	}
	return t.Execute(w, ctx)
}

// Report renders the post-execute report markdown.
func Report(w io.Writer, ctx *ReportRenderContext) error {
	t, err := loadTemplate("report.md.tmpl")
	if err != nil {
		return err
	}
	return t.Execute(w, ctx)
}

func loadTemplate(name string) (*template.Template, error) {
	raw, err := templatesFS.ReadFile("templates/" + name)
	if err != nil {
		return nil, fmt.Errorf("load template %s: %w", name, err)
	}
	return template.New(name).Funcs(FuncMap()).Parse(string(raw))
}

// FuncMap returns the helpers registered for every template (SPEC §11.4).
func FuncMap() template.FuncMap {
	return template.FuncMap{
		"add":             func(a, b int) int { return a + b },
		"sub":             func(a, b int) int { return a - b },
		"join":            strings.Join,
		"count_severity":  countSeverity,
		"count_validated": countValidated,
		"redact":          func(s string) string { return s }, // wired in defenseInDepthRedact below
		"default":         defaultStr,
	}
}

func countSeverity(items []plan.PlanItem, sev string) int {
	n := 0
	target := plan.Severity(sev)
	for _, it := range items {
		if it.Severity == target {
			n++
		}
	}
	return n
}

func countValidated(items []plan.PlanItem) int {
	n := 0
	for _, it := range items {
		if it.Validated {
			n++
		}
	}
	return n
}

func defaultStr(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}
