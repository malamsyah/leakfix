package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/malamsyah/leakfix/internal/agent"
	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/render"
	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEndToEnd_DryRunPlanContainsNoLiteralSecret stitches Stage 2 (agent) +
// Stage 3 (validate + redact) + Stage 4 (render) and verifies SPEC §15:
// the rendered plan must NOT contain the literal secret value.
func TestEndToEnd_DryRunPlanContainsNoLiteralSecret(t *testing.T) {
	const literalSecret = "AKIAIOSFODNN7EXAMPLE"
	repo := makeRepo(t, map[string]string{
		"config.go": `var key = "` + literalSecret + `"`,
	})

	finalize, _ := json.Marshal(map[string]any{
		"finding_id":      "f1",
		"provider":        "aws_iam_access_key",
		"severity":        "critical",
		"validated":       true,
		"locations":       []map[string]any{{"file": "config.go", "line": 1}},
		"runbook_id":      "aws_iam_access_key",
		"agent_rationale": "validated as live; replace with env var",
	})

	mc := &scriptedClient{steps: []scriptStep{
		step("propose_code_edit", map[string]any{
			"file":         "config.go",
			"find":         `"` + literalSecret + `"`,
			"replace_with": `os.Getenv("AWS_ACCESS_KEY_ID")`,
			"env_var_name": "AWS_ACCESS_KEY_ID",
			"rationale":    "literal -> env",
		}),
		step("finalize_plan_item", map[string]any{"plan_item_json": string(finalize)}),
	}}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID:        "f1",
		RuleID:    "kingfisher.aws.access_key",
		Secret:    literalSecret,
		Validated: true,
		Locations: []scanner.Location{{File: "config.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)

	p := &plan.Plan{
		RepoPath:    repo,
		BaseBranch:  "main",
		GeneratedAt: time.Now().UTC(),
		LeakfixVer:  "test",
		Items:       items,
	}
	require.NoError(t, p.Validate())

	red, err := p.Redact([]string{literalSecret})
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, render.Plan(&buf, red))
	out := buf.String()

	// The literal secret value MUST NOT appear in the rendered plan.
	assert.NotContains(t, out, literalSecret, "rendered plan must never contain literal secret value")

	// The redaction placeholder should appear instead.
	assert.True(t,
		strings.Contains(out, plan.Placeholder(literalSecret)) || strings.Contains(out, "[REDACTED]"),
		"expected a redaction placeholder; got: %s", out)

	// The plan should still convey the intent.
	assert.Contains(t, out, "AWS IAM Access Key")
	assert.Contains(t, out, "AWS_ACCESS_KEY_ID")
	assert.Contains(t, out, "Revocation steps")
}
