package render_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/render"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func samplePlan() *plan.Plan {
	return &plan.Plan{
		RepoPath:      "/tmp/repo",
		BaseBranch:    "main",
		GeneratedAt:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		KingfisherVer: "0.6.2",
		LeakfixVer:    "v1",
		Items: []plan.PlanItem{{
			FindingID:       "f1",
			Provider:        "aws_iam_access_key",
			DisplayName:     "AWS IAM Access Key",
			Severity:        plan.SeverityCritical,
			Validated:       true,
			Locations:       []plan.Location{{File: "a.go", Line: 10}},
			RunbookID:       "aws_iam_access_key",
			RevocationSteps: []string{"Revoke key", "Rotate key"},
			ConsoleURL:      "https://console.aws.amazon.com/iam/home",
			CodeEdits: []plan.CodeEdit{{
				File:       "a.go",
				OldContent: `key = "AKIA…[REDACTED]…MPLE"`,
				NewContent: `key = os.Getenv("AWS_ACCESS_KEY_ID")`,
				EnvVarName: "AWS_ACCESS_KEY_ID",
				Rationale:  "literal -> env",
			}},
			AgentRationale: "validated as live by Kingfisher",
		}},
	}
}

func TestPlanTemplateRenders(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, render.Plan(&buf, samplePlan()))
	out := buf.String()
	assert.Contains(t, out, "# Remediation plan")
	assert.Contains(t, out, "AWS IAM Access Key")
	assert.Contains(t, out, "AWS_ACCESS_KEY_ID")
	assert.Contains(t, out, "Revoke key")
	assert.NotContains(t, out, "AKIAIOSFODNN7EXAMPLE", "literal secret must not appear")
}

func TestPRBodyRenders(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, render.PRBody(&buf, &render.PRRenderContext{Plan: samplePlan(), IssueNumber: 42}))
	out := buf.String()
	assert.Contains(t, out, "Replace leaked secrets")
	assert.Contains(t, out, "Tracking issue: #42")
	assert.Contains(t, out, "AWS_ACCESS_KEY_ID")
}

func TestIssueBodyRenders(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, render.IssueBody(&buf, &render.IssueRenderContext{Plan: samplePlan(), PRNumber: 7}))
	out := buf.String()
	assert.Contains(t, out, "PR #7")
	assert.Contains(t, out, "Key revoked")
}

func TestReportRenders(t *testing.T) {
	var buf bytes.Buffer
	ctx := &render.ReportRenderContext{
		Plan:       samplePlan(),
		PRURL:      "https://github.com/x/y/pull/1",
		IssueURL:   "https://github.com/x/y/issues/2",
		BranchName: "leakfix/remediate-abcd1234",
		Failures:   []render.ExecutionFailure{{File: "z.go", Reason: "file changed"}},
	}
	require.NoError(t, render.Report(&buf, ctx))
	out := buf.String()
	assert.Contains(t, out, "leakfix/remediate-abcd1234")
	assert.Contains(t, out, "Could not apply automatically")
	assert.Contains(t, out, "z.go")
}

func TestPRBody_NoIssue(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, render.PRBody(&buf, &render.PRRenderContext{Plan: samplePlan(), IssueNumber: 0}))
	out := buf.String()
	assert.NotContains(t, out, "Tracking issue: #")
}

func TestPlanTemplateAcceptanceCriterion_NoLiteralSecret(t *testing.T) {
	const literalSecret = "AKIAIOSFODNN7EXAMPLE"
	p := samplePlan()
	// Pre-redact: simulate the secret being there.
	p.Items[0].CodeEdits[0].OldContent = `key = "` + literalSecret + `"`
	red, err := p.Redact([]string{literalSecret})
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, render.Plan(&buf, red))
	assert.NotContains(t, buf.String(), literalSecret)
}
