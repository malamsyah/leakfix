package agent_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/malamsyah/leakfix/internal/agent"
	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiLocationCollapse verifies that one finding with three locations
// produces one PlanItem with three CodeEdits, all sharing the same env var.
func TestMultiLocationCollapse(t *testing.T) {
	files := map[string]string{
		"a.go": `key1 = "AKIA0000ALPHA1234"`,
		"b.go": `key2 = "AKIA0000ALPHA1234"`,
		"c.go": `key3 = "AKIA0000ALPHA1234"`,
	}
	repo := makeRepo(t, files)

	finalize, _ := json.Marshal(map[string]any{
		"finding_id": "f1",
		"provider":   "aws_iam_access_key",
		"severity":   "critical",
		"locations": []map[string]any{
			{"file": "a.go", "line": 1},
			{"file": "b.go", "line": 1},
			{"file": "c.go", "line": 1},
		},
		"runbook_id":      "aws_iam_access_key",
		"agent_rationale": "same secret in 3 files",
	})

	mc := &scriptedClient{
		steps: []scriptStep{
			step("propose_code_edit", map[string]any{"file": "a.go", "find": `"AKIA…[REDACTED]…1234"`, "replace_with": `os.Getenv("AWS_ACCESS_KEY_ID")`, "env_var_name": "AWS_ACCESS_KEY_ID", "rationale": "x"}),
			step("propose_code_edit", map[string]any{"file": "b.go", "find": `"AKIA…[REDACTED]…1234"`, "replace_with": `os.Getenv("AWS_ACCESS_KEY_ID")`, "env_var_name": "AWS_ACCESS_KEY_ID", "rationale": "x"}),
			step("propose_code_edit", map[string]any{"file": "c.go", "find": `"AKIA…[REDACTED]…1234"`, "replace_with": `os.Getenv("AWS_ACCESS_KEY_ID")`, "env_var_name": "AWS_ACCESS_KEY_ID", "rationale": "x"}),
			step("finalize_plan_item", map[string]any{"plan_item_json": string(finalize)}),
		},
	}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID:     "f1",
		RuleID: "kingfisher.aws.access_key",
		Secret: "AKIA0000ALPHA1234",
		Locations: []scanner.Location{
			{File: "a.go", Line: 1},
			{File: "b.go", Line: 1},
			{File: "c.go", Line: 1},
		},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Len(t, items[0].Locations, 3)
	assert.Len(t, items[0].CodeEdits, 3)
	for _, e := range items[0].CodeEdits {
		assert.Equal(t, "AWS_ACCESS_KEY_ID", e.EnvVarName)
	}
}

func step(name string, input any) scriptStep {
	return func(_ agent.Request) (agent.Response, error) {
		return mkResp("tool_use", toolUse(newID(), name, input)), nil
	}
}
