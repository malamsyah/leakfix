package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/malamsyah/leakfix/internal/runbooks"
	"github.com/malamsyah/leakfix/internal/scanner"
)

// stagedEdit is what propose_code_edit accumulates per finding.
type stagedEdit struct {
	File       string
	Find       string
	Replace    string
	EnvVarName string
	Rationale  string
}

// toolHost backs the LLM tools and tracks per-finding state.
type toolHost struct {
	repo      string
	registry  *runbooks.Registry
	maxRead   int
	finding   scanner.Finding
	staged    []stagedEdit
	finalized json.RawMessage
}

func newToolHost(repo string, reg *runbooks.Registry, maxRead int, finding scanner.Finding) *toolHost {
	return &toolHost{
		repo:     repo,
		registry: reg,
		maxRead:  maxRead,
		finding:  finding,
	}
}

// ToolDefs returns the JSON schemas exposed to the LLM. Schemas are kept
// permissive — tool implementations re-validate inputs.
func ToolDefs() []ToolDef {
	defs := []struct {
		name, desc string
		schema     string
	}{
		{"list_providers", "List the bundled runbook provider IDs.", `{"type":"object","properties":{}}`},
		{"lookup_runbook", "Return the runbook YAML for a provider id (or '_generic').", `{"type":"object","properties":{"provider_id":{"type":"string"}},"required":["provider_id"]}`},
		{"read_file", "Read a file from the target repo. Path must be repo-relative.", `{"type":"object","properties":{"repo_relative_path":{"type":"string"}},"required":["repo_relative_path"]}`},
		{"assess_finding", "Return Kingfisher metadata for the given finding id.", `{"type":"object","properties":{"finding_id":{"type":"string"}},"required":["finding_id"]}`},
		{"propose_code_edit", "Stage a code edit. The 'find' string must match the file content exactly once.", `{"type":"object","properties":{"file":{"type":"string"},"find":{"type":"string"},"replace_with":{"type":"string"},"env_var_name":{"type":"string"},"rationale":{"type":"string"}},"required":["file","find","replace_with","env_var_name","rationale"]}`},
		{"finalize_plan_item", "Commit the assembled PlanItem JSON.", `{"type":"object","properties":{"plan_item_json":{"type":"string"}},"required":["plan_item_json"]}`},
	}
	out := make([]ToolDef, len(defs))
	for i, d := range defs {
		out[i] = ToolDef{Name: d.name, Description: d.desc, InputSchema: json.RawMessage(d.schema)}
	}
	return out
}

// dispatch invokes the named tool with the given JSON input. Returns the
// result string sent back to the LLM and a boolean isError flag.
func (h *toolHost) dispatch(name string, input json.RawMessage) (string, bool) {
	switch name {
	case "list_providers":
		return h.listProviders()
	case "lookup_runbook":
		return h.lookupRunbook(input)
	case "read_file":
		return h.readFile(input)
	case "assess_finding":
		return h.assessFinding(input)
	case "propose_code_edit":
		return h.proposeCodeEdit(input)
	case "finalize_plan_item":
		return h.finalizePlanItem(input)
	default:
		return fmt.Sprintf("unknown tool %q", name), true
	}
}

func (h *toolHost) listProviders() (string, bool) {
	out, _ := json.Marshal(h.registry.Providers())
	return string(out), false
}

func (h *toolHost) lookupRunbook(input json.RawMessage) (string, bool) {
	var args struct {
		ProviderID string `json:"provider_id"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return err.Error(), true
	}
	rb, ok := h.registry.ByID(args.ProviderID)
	if !ok {
		rb, _ = h.registry.ByID(runbooks.GenericID)
	}
	out, _ := json.Marshal(map[string]any{
		"id":                     rb.ID,
		"display_name":           rb.DisplayName,
		"severity_default":       rb.SeverityDefault,
		"revocation_steps":       rb.Revocation.Steps,
		"revocation_console_url": rb.Revocation.ConsoleURL,
		"replacement_pattern":    rb.ReplacementPattern,
		"env_var_suggested_name": rb.EnvVarSuggestedName,
	})
	return string(out), false
}

func (h *toolHost) readFile(input json.RawMessage) (string, bool) {
	var args struct {
		Path string `json:"repo_relative_path"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return err.Error(), true
	}
	full, err := safeJoin(h.repo, args.Path)
	if err != nil {
		return err.Error(), true
	}
	info, err := os.Lstat(full)
	if err != nil {
		return err.Error(), true
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		// Resolve and re-check that the target stays inside the repo.
		resolved, rerr := filepath.EvalSymlinks(full)
		if rerr != nil {
			return rerr.Error(), true
		}
		if _, err := safeJoin(h.repo, mustRel(h.repo, resolved)); err != nil {
			return "symlink escapes repository", true
		}
		full = resolved
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return err.Error(), true
	}
	if len(data) > h.maxRead {
		data = data[:h.maxRead]
	}
	return string(data), false
}

func (h *toolHost) assessFinding(input json.RawMessage) (string, bool) {
	var args struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return err.Error(), true
	}
	if args.FindingID != h.finding.ID && args.FindingID != h.finding.SecretHash {
		return fmt.Sprintf("finding %q not in scope for this turn", args.FindingID), true
	}
	out, _ := json.Marshal(map[string]any{
		"finding_id": h.finding.ID,
		"rule_id":    h.finding.RuleID,
		"validated":  h.finding.Validated,
		"locations":  h.finding.Locations,
		"access_map": h.finding.AccessMap,
	})
	return string(out), false
}

func (h *toolHost) proposeCodeEdit(input json.RawMessage) (string, bool) {
	var args struct {
		File       string `json:"file"`
		Find       string `json:"find"`
		Replace    string `json:"replace_with"`
		EnvVarName string `json:"env_var_name"`
		Rationale  string `json:"rationale"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return err.Error(), true
	}
	if args.File == "" || args.Find == "" || args.Replace == "" || args.EnvVarName == "" {
		return `{"ok":false,"error_reason":"file, find, replace_with, env_var_name are all required"}`, false
	}

	full, err := safeJoin(h.repo, args.File)
	if err != nil {
		return fmt.Sprintf(`{"ok":false,"error_reason":%q}`, err.Error()), false
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return fmt.Sprintf(`{"ok":false,"error_reason":%q}`, err.Error()), false
	}
	occurrences := strings.Count(string(data), args.Find)
	switch occurrences {
	case 0:
		return `{"ok":false,"error_reason":"find string not present in file"}`, false
	case 1:
		// fall through to stage
	default:
		return `{"ok":false,"error_reason":"find string is ambiguous; provide more context"}`, false
	}

	h.staged = append(h.staged, stagedEdit{
		File:       args.File,
		Find:       args.Find,
		Replace:    args.Replace,
		EnvVarName: args.EnvVarName,
		Rationale:  args.Rationale,
	})
	return `{"ok":true}`, false
}

func (h *toolHost) finalizePlanItem(input json.RawMessage) (string, bool) {
	var args struct {
		Body string `json:"plan_item_json"`
	}
	if err := json.Unmarshal(input, &args); err != nil {
		return err.Error(), true
	}
	if !json.Valid([]byte(args.Body)) {
		return "plan_item_json must be valid JSON", true
	}
	h.finalized = json.RawMessage(args.Body)
	return `{"finalized":true}`, false
}

func safeJoin(repo, rel string) (string, error) {
	if repo == "" {
		return "", errors.New("repo path empty")
	}
	cleaned := filepath.Clean(rel)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute paths not allowed: %q", rel)
	}
	full := filepath.Join(repo, cleaned)
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return "", err
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	r, err := filepath.Rel(repoAbs, fullAbs)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(r, "..") {
		return "", fmt.Errorf("path escapes repository: %q", rel)
	}
	return fullAbs, nil
}

func mustRel(base, target string) string {
	r, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return r
}
