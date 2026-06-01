package agent_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/malamsyah/leakfix/internal/agent"
	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadFile_RedactsKnownSecrets verifies the redaction boundary: when
// the agent calls read_file, the literal secret value never appears in the
// tool result the LLM sees.
func TestReadFile_RedactsKnownSecrets(t *testing.T) {
	const literal = "AKIAIOSFODNN7EXAMPLE"
	repo := makeRepo(t, map[string]string{
		"config.go": "var key = \"" + literal + "\"\n",
	})

	finalize, _ := json.Marshal(map[string]any{
		"finding_id":      "f1",
		"provider":        "_generic",
		"severity":        "high",
		"locations":       []map[string]any{{"file": "config.go", "line": 1}},
		"runbook_id":      "_generic",
		"agent_rationale": "checked",
	})

	var readResult string
	mc := &scriptedClient{steps: []scriptStep{
		step("read_file", map[string]any{"repo_relative_path": "config.go"}),
		func(req agent.Request) (agent.Response, error) {
			// The previous tool result is what the LLM would see. Capture it.
			last := req.Messages[len(req.Messages)-1]
			for _, b := range last.Content {
				if b.Type == "tool_result" {
					readResult = b.Result
				}
			}
			return mkResp("tool_use", toolUse(newID(), "finalize_plan_item", map[string]any{"plan_item_json": string(finalize)})), nil
		},
	}}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID: "f1", RuleID: "kingfisher.x",
		Secret:    literal,
		Locations: []scanner.Location{{File: "config.go", Line: 1}},
	}
	_, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)

	require.NotEmpty(t, readResult, "expected to capture a tool_result")
	assert.NotContains(t, readResult, literal, "literal secret must not appear in read_file output sent to LLM")
	assert.Contains(t, readResult, plan.Placeholder(literal), "expected redaction placeholder in read_file output")
}

// TestProposeCodeEdit_AcceptsPlaceholderFind verifies the agent can submit
// the placeholder it saw via read_file, and the tool reverse-maps it back
// to validate against the on-disk file. The resulting CodeEdit.OldContent
// is the real secret (Stage 5 apply needs it).
func TestProposeCodeEdit_AcceptsPlaceholderFind(t *testing.T) {
	const literal = "AKIAIOSFODNN7EXAMPLE"
	repo := makeRepo(t, map[string]string{
		"config.go": "key = \"" + literal + "\"\n",
	})

	finalize, _ := json.Marshal(map[string]any{
		"finding_id":      "f1",
		"provider":        "aws_iam_access_key",
		"severity":        "critical",
		"locations":       []map[string]any{{"file": "config.go", "line": 1}},
		"runbook_id":      "aws_iam_access_key",
		"agent_rationale": "ok",
	})

	mc := &scriptedClient{steps: []scriptStep{
		step("propose_code_edit", map[string]any{
			"file":         "config.go",
			"find":         "\"" + plan.Placeholder(literal) + "\"",
			"replace_with": `os.Getenv("AWS_ACCESS_KEY_ID")`,
			"env_var_name": "AWS_ACCESS_KEY_ID",
			"rationale":    "placeholder -> env",
		}),
		step("finalize_plan_item", map[string]any{"plan_item_json": string(finalize)}),
	}}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID: "f1", RuleID: "kingfisher.aws.access_key",
		Secret:    literal,
		Locations: []scanner.Location{{File: "config.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Len(t, items[0].CodeEdits, 1)
	assert.Equal(t, "\""+literal+"\"", items[0].CodeEdits[0].OldContent,
		"OldContent must hold the real secret (Stage 5 apply needs it)")
}

// TestScrubbingClient_BlocksLiteralLeak verifies the fail-closed scrubber:
// if a misbehaving agent or future tool injects a literal secret into the
// outbound payload, the request is refused and the literal never reaches
// the wire. The error message itself uses the placeholder.
func TestScrubbingClient_BlocksLiteralLeak(t *testing.T) {
	const literal = "AKIAIOSFODNN7EXAMPLE"
	repo := makeRepo(t, map[string]string{
		"config.go": "key = \"" + literal + "\"\n",
	})

	// The scripted client immediately returns text that contains the literal
	// secret. The next turn's request would replay that text — the scrubber
	// must refuse to send it.
	mc := &scriptedClient{steps: []scriptStep{
		func(_ agent.Request) (agent.Response, error) {
			return mkResp("tool_use",
				agent.ContentBlock{Type: "text", Text: "I found " + literal + " in the file."},
				toolUse(newID(), "list_providers", map[string]any{}),
			), nil
		},
		// This step would only run if the scrubber failed.
		step("list_providers", map[string]any{}),
	}}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID: "f1", RuleID: "kingfisher.x",
		Secret:    literal,
		Locations: []scanner.Location{{File: "config.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err, "scrubber failure becomes a fallback PlanItem, not a top-level error")
	require.Len(t, items, 1)
	// Fallback rationale must reference the refusal and must NOT contain the literal.
	assert.Contains(t, items[0].AgentRationale, "refusing to send")
	assert.NotContains(t, items[0].AgentRationale, literal,
		"refusal error must not echo the literal secret")
}

// TestAssemblePlanItem_ReversesAgentSuppliedOldContent guards the second
// reverse-mapping site: when the agent puts placeholders inside the
// finalize_plan_item code_edits[] payload (rather than going through
// propose_code_edit), assemblePlanItem must still produce a real secret in
// OldContent so apply works.
func TestAssemblePlanItem_ReversesAgentSuppliedOldContent(t *testing.T) {
	const literal = "AKIAIOSFODNN7EXAMPLE"
	repo := makeRepo(t, map[string]string{
		"config.go": "key = \"" + literal + "\"\n",
	})

	finalize, _ := json.Marshal(map[string]any{
		"finding_id":      "f1",
		"provider":        "aws_iam_access_key",
		"severity":        "critical",
		"locations":       []map[string]any{{"file": "config.go", "line": 1}},
		"runbook_id":      "aws_iam_access_key",
		"agent_rationale": "ok",
		"code_edits": []map[string]any{{
			"file":         "config.go",
			"old_content":  "\"" + plan.Placeholder(literal) + "\"",
			"new_content":  `os.Getenv("AWS_ACCESS_KEY_ID")`,
			"env_var_name": "AWS_ACCESS_KEY_ID",
			"rationale":    "inline",
		}},
	})

	mc := &scriptedClient{steps: []scriptStep{
		step("finalize_plan_item", map[string]any{"plan_item_json": string(finalize)}),
	}}

	ag := agent.New(mc, loadReg(t), repo)
	finding := scanner.Finding{
		ID: "f1", RuleID: "kingfisher.aws.access_key",
		Secret:    literal,
		Locations: []scanner.Location{{File: "config.go", Line: 1}},
	}
	items, err := ag.PlanForFindings(context.Background(), []scanner.Finding{finding})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Len(t, items[0].CodeEdits, 1)
	got := items[0].CodeEdits[0].OldContent
	assert.True(t, strings.Contains(got, literal),
		"agent-supplied placeholder must be reversed to the literal in OldContent; got %q", got)
}
