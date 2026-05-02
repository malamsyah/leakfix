package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/malamsyah/leakfix/internal/runbooks"
	"github.com/malamsyah/leakfix/internal/scanner"
)

// Agent orchestrates the per-finding planning loop.
type Agent struct {
	client     Client
	registry   *runbooks.Registry
	repo       string
	model      string
	guardrails Guardrails
}

// New creates an Agent. Use DefaultClient() if you want the live Anthropic client.
func New(client Client, reg *runbooks.Registry, repo string) *Agent {
	model := os.Getenv("LEAKFIX_MODEL")
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	return &Agent{
		client:     client,
		registry:   reg,
		repo:       repo,
		model:      model,
		guardrails: DefaultGuardrails(),
	}
}

// SetGuardrails replaces the default guardrails (used by tests).
func (a *Agent) SetGuardrails(g Guardrails) { a.guardrails = g }

// SetModel overrides the LLM model name.
func (a *Agent) SetModel(model string) { a.model = model }

// PlanForFindings runs the per-finding loop and returns one PlanItem per
// finding (in order). Sequential by design (SPEC §10).
func (a *Agent) PlanForFindings(ctx context.Context, findings []scanner.Finding) ([]plan.PlanItem, error) {
	if len(findings) > a.guardrails.MaxTotalFindings {
		return nil, fmt.Errorf("findings (%d) exceed LEAKFIX_MAX_FINDINGS (%d)", len(findings), a.guardrails.MaxTotalFindings)
	}
	totalCtx, cancel := context.WithTimeout(ctx, a.guardrails.TotalTimeout)
	defer cancel()

	items := make([]plan.PlanItem, 0, len(findings))
	for _, f := range findings {
		item, err := a.planForFinding(totalCtx, f)
		if err != nil {
			// Don't fail the whole run — record a fallback item with rationale.
			items = append(items, a.fallbackItem(f, err.Error()))
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (a *Agent) planForFinding(ctx context.Context, f scanner.Finding) (plan.PlanItem, error) {
	perCtx, cancel := context.WithTimeout(ctx, a.guardrails.PerFindingTimeout)
	defer cancel()

	host := newToolHost(a.repo, a.registry, a.guardrails.MaxReadFileBytes, f)
	messages := []Message{
		{
			Role:    "user",
			Content: []ContentBlock{{Type: "text", Text: renderUserPrompt(f)}},
		},
	}

	for iter := 0; iter < a.guardrails.MaxIterationsPerFinding; iter++ {
		resp, err := a.client.Complete(perCtx, Request{
			Model:     a.model,
			System:    SystemPromptPlan,
			Messages:  messages,
			Tools:     ToolDefs(),
			MaxTokens: a.guardrails.MaxOutputTokens,
		})
		if err != nil {
			return plan.PlanItem{}, fmt.Errorf("llm call: %w", err)
		}

		messages = append(messages, Message{Role: "assistant", Content: resp.Content})

		toolUses := []ContentBlock{}
		for _, block := range resp.Content {
			if block.Type == "tool_use" {
				toolUses = append(toolUses, block)
			}
		}

		if len(toolUses) == 0 {
			break
		}

		results := make([]ContentBlock, 0, len(toolUses))
		for _, tu := range toolUses {
			out, isErr := host.dispatch(tu.Name, tu.Input)
			results = append(results, ContentBlock{
				Type:      "tool_result",
				ToolUseID: tu.ToolUseID,
				Result:    out,
				IsError:   isErr,
			})
		}
		messages = append(messages, Message{Role: "user", Content: results})

		if host.finalized != nil {
			break
		}

		if resp.StopReason == "end_turn" {
			break
		}
	}

	if host.finalized == nil {
		return a.fallbackItem(f, "agent loop exceeded iterations; falling back to runbook defaults"), nil
	}

	item, err := assemblePlanItem(host.finalized, f, host.staged, a.registry)
	if err != nil {
		return a.fallbackItem(f, "agent finalize unparsable: "+err.Error()), nil
	}
	return item, nil
}

func renderUserPrompt(f scanner.Finding) string {
	locs := strings.Builder{}
	for _, loc := range f.Locations {
		fmt.Fprintf(&locs, "  - %s:%d\n", loc.File, loc.Line)
	}
	access := "_no access map available_"
	if f.AccessMap != nil && f.AccessMap.Identity != "" {
		access = fmt.Sprintf("Access map: identity=%s permissions=%v resources=%v", f.AccessMap.Identity, f.AccessMap.Permissions, f.AccessMap.Resources)
	}
	out := UserPromptTemplateFinding
	out = strings.ReplaceAll(out, "{{FINDING_ID}}", f.ID)
	out = strings.ReplaceAll(out, "{{RULE_ID}}", f.RuleID)
	out = strings.ReplaceAll(out, "{{VALIDATED}}", fmt.Sprintf("%t", f.Validated))
	out = strings.ReplaceAll(out, "{{LOCATIONS}}", strings.TrimRight(locs.String(), "\n"))
	out = strings.ReplaceAll(out, "{{ACCESS_MAP_BLOCK}}", access)
	return out
}

// fallbackItem is the agent-failed item; we still need a usable plan entry.
func (a *Agent) fallbackItem(f scanner.Finding, rationale string) plan.PlanItem {
	rb, _ := a.registry.Match(f.RuleID)
	if rb == nil {
		rb, _ = a.registry.ByID(runbooks.GenericID)
	}
	locs := make([]plan.Location, len(f.Locations))
	for i, l := range f.Locations {
		locs[i] = plan.Location{File: l.File, Line: l.Line, CommitSHA: l.CommitSHA, BlobURL: l.BlobURL, CommitURL: l.CommitURL}
	}
	return plan.PlanItem{
		FindingID:       f.ID,
		Provider:        rb.ID,
		DisplayName:     rb.DisplayName,
		Severity:        plan.ParseSeverity(rb.SeverityDefault),
		Validated:       f.Validated,
		Locations:       locs,
		RunbookID:       rb.ID,
		RevocationSteps: append([]string(nil), rb.Revocation.Steps...),
		ConsoleURL:      rb.Revocation.ConsoleURL,
		AgentRationale:  rationale,
	}
}

func assemblePlanItem(raw json.RawMessage, f scanner.Finding, staged []stagedEdit, reg *runbooks.Registry) (plan.PlanItem, error) {
	var draft struct {
		FindingID       string          `json:"finding_id"`
		Provider        string          `json:"provider"`
		DisplayName     string          `json:"display_name"`
		Severity        string          `json:"severity"`
		Validated       bool            `json:"validated"`
		Locations       []plan.Location `json:"locations"`
		RunbookID       string          `json:"runbook_id"`
		RevocationSteps []string        `json:"revocation_steps"`
		ConsoleURL      string          `json:"console_url"`
		CodeEdits       []struct {
			File       string `json:"file"`
			OldContent string `json:"old_content"`
			NewContent string `json:"new_content"`
			EnvVarName string `json:"env_var_name"`
			Rationale  string `json:"rationale"`
		} `json:"code_edits"`
		AgentRationale string `json:"agent_rationale"`
	}
	if err := json.Unmarshal(raw, &draft); err != nil {
		return plan.PlanItem{}, err
	}

	provider := draft.Provider
	if provider == "" {
		provider = draft.RunbookID
	}
	if provider == "" {
		rb, _ := reg.Match(f.RuleID)
		provider = rb.ID
	}

	rb, ok := reg.ByID(provider)
	if !ok {
		rb, _ = reg.ByID(runbooks.GenericID)
		provider = rb.ID
	}

	if draft.FindingID == "" {
		draft.FindingID = f.ID
	}
	if draft.DisplayName == "" {
		draft.DisplayName = rb.DisplayName
	}
	if len(draft.RevocationSteps) == 0 {
		draft.RevocationSteps = append([]string(nil), rb.Revocation.Steps...)
	}
	if draft.ConsoleURL == "" {
		draft.ConsoleURL = rb.Revocation.ConsoleURL
	}
	if len(draft.Locations) == 0 {
		for _, loc := range f.Locations {
			draft.Locations = append(draft.Locations, plan.Location{File: loc.File, Line: loc.Line, CommitSHA: loc.CommitSHA, BlobURL: loc.BlobURL, CommitURL: loc.CommitURL})
		}
	} else {
		// LLM-supplied locations don't carry URLs; enrich from scanner data
		// when file+line matches.
		for i := range draft.Locations {
			loc := &draft.Locations[i]
			for _, src := range f.Locations {
				if src.File == loc.File && (src.Line == loc.Line || loc.Line == 0) {
					if loc.BlobURL == "" {
						loc.BlobURL = src.BlobURL
					}
					if loc.CommitURL == "" {
						loc.CommitURL = src.CommitURL
					}
					if loc.CommitSHA == "" {
						loc.CommitSHA = src.CommitSHA
					}
					break
				}
			}
		}
	}

	// If the agent's code_edits are empty but staged ones exist, prefer the staged set.
	edits := make([]plan.CodeEdit, 0, len(staged)+len(draft.CodeEdits))
	if len(draft.CodeEdits) > 0 {
		for _, e := range draft.CodeEdits {
			edits = append(edits, plan.CodeEdit{
				File:       e.File,
				OldContent: e.OldContent,
				NewContent: e.NewContent,
				EnvVarName: e.EnvVarName,
				Rationale:  e.Rationale,
			})
		}
	} else {
		for _, s := range staged {
			edits = append(edits, plan.CodeEdit{
				File:       s.File,
				OldContent: s.Find,
				NewContent: s.Replace,
				EnvVarName: s.EnvVarName,
				Rationale:  s.Rationale,
			})
		}
	}

	severity := plan.ParseSeverity(draft.Severity)
	if draft.Severity == "" {
		severity = plan.ParseSeverity(rb.SeverityDefault)
	}

	item := plan.PlanItem{
		FindingID:       draft.FindingID,
		Provider:        provider,
		DisplayName:     draft.DisplayName,
		Severity:        severity,
		Validated:       draft.Validated || f.Validated,
		Locations:       draft.Locations,
		RunbookID:       provider,
		RevocationSteps: draft.RevocationSteps,
		ConsoleURL:      draft.ConsoleURL,
		CodeEdits:       edits,
		AgentRationale:  strings.TrimSpace(draft.AgentRationale),
	}
	if f.AccessMap != nil {
		item.AccessMap = &plan.AccessMap{
			Identity:    f.AccessMap.Identity,
			Permissions: f.AccessMap.Permissions,
			Resources:   f.AccessMap.Resources,
		}
	}
	return item, nil
}
