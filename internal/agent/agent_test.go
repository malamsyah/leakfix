package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/malamsyah/leakfix/internal/agent"
	"github.com/malamsyah/leakfix/internal/runbooks"
	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeRepo writes file contents into a temp dir and returns the path.
func makeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
	}
	return dir
}

func loadReg(t *testing.T) *runbooks.Registry {
	t.Helper()
	reg, err := runbooks.Load()
	require.NoError(t, err)
	return reg
}

func TestPlanForFindings_HappyPath(t *testing.T) {
	const fileBody = `key = "AKIAIOSFODNN7EXAMPLE"`
	repo := makeRepo(t, map[string]string{"config.go": fileBody})

	finalizeBody := map[string]any{
		"finding_id":      "f1",
		"provider":        "aws_iam_access_key",
		"severity":        "critical",
		"validated":       true,
		"locations":       []map[string]any{{"file": "config.go", "line": 1}},
		"runbook_id":      "aws_iam_access_key",
		"agent_rationale": "validated as live",
	}
	finalizeStr, _ := json.Marshal(finalizeBody)

	mc := &scriptedClient{
		steps: []scriptStep{
			// Turn 1: agent calls propose_code_edit
			func(_ agent.Request) (agent.Response, error) {
				return mkResp("tool_use",
					toolUse(newID(), "propose_code_edit", map[string]any{
						"file":         "config.go",
						"find":         `"AKIAIOSFODNN7EXAMPLE"`,
						"replace_with": `os.Getenv("AWS_ACCESS_KEY_ID")`,
						"env_var_name": "AWS_ACCESS_KEY_ID",
						"rationale":    "literal -> env",
					}),
				), nil
			},
			// Turn 2: agent calls finalize_plan_item
			func(_ agent.Request) (agent.Response, error) {
				return mkResp("tool_use",
					toolUse(newID(), "finalize_plan_item", map[string]any{
						"plan_item_json": string(finalizeStr),
					}),
				), nil
			},
		},
	}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID:        "f1",
		RuleID:    "kingfisher.aws.access_key",
		Secret:    "AKIAIOSFODNN7EXAMPLE",
		Validated: true,
		Locations: []scanner.Location{{File: "config.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "aws_iam_access_key", items[0].Provider)
	require.Len(t, items[0].CodeEdits, 1)
	assert.Equal(t, "AWS_ACCESS_KEY_ID", items[0].CodeEdits[0].EnvVarName)
	assert.Contains(t, items[0].CodeEdits[0].OldContent, "AKIAIOSFODNN7EXAMPLE")
}

func TestPlanForFindings_FallsBackToGenericForUnknownProvider(t *testing.T) {
	repo := makeRepo(t, map[string]string{"x.txt": "literal-secret-xyz"})

	finalizeBody := map[string]any{
		"finding_id":      "f1",
		"provider":        "_generic",
		"severity":        "high",
		"locations":       []map[string]any{{"file": "x.txt", "line": 1}},
		"runbook_id":      "_generic",
		"agent_rationale": "no specific runbook",
	}
	finalizeStr, _ := json.Marshal(finalizeBody)

	mc := &scriptedClient{
		steps: []scriptStep{
			func(_ agent.Request) (agent.Response, error) {
				return mkResp("tool_use",
					toolUse(newID(), "finalize_plan_item", map[string]any{"plan_item_json": string(finalizeStr)}),
				), nil
			},
		},
	}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID:        "f1",
		RuleID:    "kingfisher.never.heard.of",
		Secret:    "literal-secret-xyz",
		Locations: []scanner.Location{{File: "x.txt", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Equal(t, "_generic", items[0].Provider)
	assert.NotEmpty(t, items[0].RevocationSteps)
}

func TestProposeCodeEdit_FindStringNotPresent(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.go": "content"})

	finalizeBody, _ := json.Marshal(map[string]any{
		"finding_id":      "f1",
		"provider":        "_generic",
		"severity":        "high",
		"locations":       []map[string]any{{"file": "a.go", "line": 1}},
		"runbook_id":      "_generic",
		"agent_rationale": "tried",
	})

	mc := &scriptedClient{
		steps: []scriptStep{
			// Turn 1: bad find string
			func(_ agent.Request) (agent.Response, error) {
				return mkResp("tool_use",
					toolUse(newID(), "propose_code_edit", map[string]any{
						"file": "a.go", "find": "NOT_THERE", "replace_with": "x",
						"env_var_name": "X", "rationale": "test",
					}),
				), nil
			},
			// Turn 2: agent gives up and finalizes
			func(req agent.Request) (agent.Response, error) {
				// confirm the previous tool result reported the error
				lastUser := req.Messages[len(req.Messages)-1]
				require.Equal(t, "user", lastUser.Role)
				found := false
				for _, b := range lastUser.Content {
					if b.Type == "tool_result" && containsBoth(b.Result, "ok", "false") {
						found = true
					}
				}
				require.True(t, found, "expected error tool_result")
				return mkResp("tool_use",
					toolUse(newID(), "finalize_plan_item", map[string]any{
						"plan_item_json": string(finalizeBody),
					}),
				), nil
			},
		},
	}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID:        "f1",
		RuleID:    "kingfisher.x",
		Secret:    "NOT_THERE",
		Locations: []scanner.Location{{File: "a.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Empty(t, items[0].CodeEdits, "no edit should be staged after the find-string failure")
}

func TestPlanForFindings_IterationLimitFallsBack(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.go": "x"})

	// Loops forever calling list_providers — never finalizes.
	mc := &scriptedClient{
		steps: []scriptStep{},
	}
	for i := 0; i < 20; i++ {
		mc.steps = append(mc.steps, func(_ agent.Request) (agent.Response, error) {
			return mkResp("tool_use",
				toolUse(newID(), "list_providers", map[string]any{}),
			), nil
		})
	}

	ag := agent.New(mc, loadReg(t), repo)
	g := agent.DefaultGuardrails()
	g.MaxIterationsPerFinding = 3
	ag.SetGuardrails(g)

	finding := scanner.Finding{
		ID:        "f1",
		RuleID:    "kingfisher.aws.access_key",
		Secret:    "x",
		Locations: []scanner.Location{{File: "a.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.Contains(t, items[0].AgentRationale, "exceeded iterations")
}

func TestPlanForFindings_TooManyFindingsErrors(t *testing.T) {
	mc := &scriptedClient{}
	ag := agent.New(mc, loadReg(t), t.TempDir())
	g := agent.DefaultGuardrails()
	g.MaxTotalFindings = 1
	ag.SetGuardrails(g)

	findings := []scanner.Finding{
		{ID: "a", RuleID: "k", Locations: []scanner.Location{{File: "x", Line: 1}}},
		{ID: "b", RuleID: "k", Locations: []scanner.Location{{File: "x", Line: 1}}},
	}
	_, err := ag.PlanForFindings(context.Background(), findings)
	assert.Error(t, err)
}

func TestSandboxedReadFile_RefusesEscape(t *testing.T) {
	repo := makeRepo(t, map[string]string{"a.txt": "hi"})
	finalizeBody, _ := json.Marshal(map[string]any{
		"finding_id":      "f1",
		"provider":        "_generic",
		"severity":        "high",
		"locations":       []map[string]any{{"file": "a.txt", "line": 1}},
		"runbook_id":      "_generic",
		"agent_rationale": "tried",
	})

	mc := &scriptedClient{
		steps: []scriptStep{
			func(_ agent.Request) (agent.Response, error) {
				return mkResp("tool_use",
					toolUse(newID(), "read_file", map[string]any{"repo_relative_path": "../etc/passwd"}),
				), nil
			},
			func(req agent.Request) (agent.Response, error) {
				lastUser := req.Messages[len(req.Messages)-1]
				escaped := false
				for _, b := range lastUser.Content {
					if b.Type == "tool_result" && b.IsError && containsAny(b.Result, "escape", "absolute", "outside") {
						escaped = true
					}
				}
				require.True(t, escaped, "read_file must refuse escapes")
				return mkResp("tool_use",
					toolUse(newID(), "finalize_plan_item", map[string]any{"plan_item_json": string(finalizeBody)}),
				), nil
			},
		},
	}
	ag := agent.New(mc, loadReg(t), repo)
	_, err := ag.PlanForFindings(context.Background(), []scanner.Finding{{
		ID: "f1", RuleID: "kingfisher.x",
		Locations: []scanner.Location{{File: "a.txt", Line: 1}},
	}})
	require.NoError(t, err)
}

func containsBoth(s, a, b string) bool {
	return contains(s, a) && contains(s, b)
}

func containsAny(s string, words ...string) bool {
	for _, w := range words {
		if contains(s, w) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
