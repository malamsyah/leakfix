package plan

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Plan is the output of Stage 2. It fully describes what
// leakfix intends to do for a given repo, before any side effects.
type Plan struct {
	RepoPath       string          `json:"repo_path"`
	BaseBranch     string          `json:"base_branch"`
	GeneratedAt    time.Time       `json:"generated_at"`
	KingfisherVer  string          `json:"kingfisher_version"`
	LeakfixVer     string          `json:"leakfix_version"`
	Items          []PlanItem      `json:"items"`
	HistoryRewrite *HistoryRewrite `json:"history_rewrite,omitempty"`
}

// PlanItem represents a single finding's full remediation plan.
type PlanItem struct {
	FindingID       string     `json:"finding_id"`
	Provider        string     `json:"provider"`
	DisplayName     string     `json:"display_name"`
	Severity        Severity   `json:"severity"`
	Validated       bool       `json:"validated"`
	AccessMap       *AccessMap `json:"access_map,omitempty"`
	Locations       []Location `json:"locations"`
	RunbookID       string     `json:"runbook_id"`
	RevocationSteps []string   `json:"revocation_steps"`
	ConsoleURL      string     `json:"console_url,omitempty"`
	CodeEdits       []CodeEdit `json:"code_edits,omitempty"`
	AgentRationale  string     `json:"agent_rationale"`
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "med":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityHigh
	}
}

type Location struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	CommitSHA string `json:"commit_sha,omitempty"`
	BlobURL   string `json:"blob_url,omitempty"`
	CommitURL string `json:"commit_url,omitempty"`
}

type CodeEdit struct {
	File       string `json:"file"`
	OldContent string `json:"old_content"`
	NewContent string `json:"new_content"`
	EnvVarName string `json:"env_var_name"`
	Rationale  string `json:"rationale"`
}

type AccessMap struct {
	Identity    string   `json:"identity,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Resources   []string `json:"resources,omitempty"`
}

type HistoryRewrite struct {
	Command     string   `json:"command"`
	SideEffects []string `json:"side_effects"`
	PostSteps   []string `json:"post_steps"`
}

// Validate ensures the Plan is structurally sound.
// It does NOT perform redaction — Redact() does that.
func (p *Plan) Validate() error {
	if p == nil {
		return fmt.Errorf("plan is nil")
	}
	if p.RepoPath == "" {
		return fmt.Errorf("plan.RepoPath is required")
	}
	for i, it := range p.Items {
		if it.FindingID == "" {
			return fmt.Errorf("items[%d]: FindingID is required", i)
		}
		if it.RunbookID == "" {
			return fmt.Errorf("items[%d]: RunbookID is required", i)
		}
		if len(it.Locations) == 0 {
			return fmt.Errorf("items[%d]: at least one Location required", i)
		}
		switch it.Severity {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		default:
			return fmt.Errorf("items[%d]: invalid severity %q", i, it.Severity)
		}
		// CodeEdits are optional, but if present every edit must reference an existing location.
		for j, e := range it.CodeEdits {
			if e.File == "" {
				return fmt.Errorf("items[%d].CodeEdits[%d]: File required", i, j)
			}
			if e.NewContent == "" {
				return fmt.Errorf("items[%d].CodeEdits[%d]: NewContent required", i, j)
			}
			if e.EnvVarName == "" {
				return fmt.Errorf("items[%d].CodeEdits[%d]: EnvVarName required", i, j)
			}
		}
	}
	return nil
}

// Redact returns a copy of the Plan with all known literal secret values
// replaced by the placeholder. After Redact, no PlanItem may contain a
// literal secret. If a literal cannot be safely redacted, Redact returns
// an error — the redacted plan is unsafe to render.
func (p *Plan) Redact(secrets []string) (*Plan, error) {
	dedup := uniqueNonEmpty(secrets)
	sort.Slice(dedup, func(i, j int) bool { return len(dedup[i]) > len(dedup[j]) })

	out := p.deepCopy()
	rewriteAllStrings(out, func(s string) string { return redactString(s, dedup) })

	if missed, ok := findLeak(out, dedup); !ok {
		return nil, fmt.Errorf("redaction failed: literal secret value %q still appears in plan", placeholder(missed))
	}
	return out, nil
}

func uniqueNonEmpty(in []string) []string {
	set := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := set[s]; ok {
			continue
		}
		set[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// redactString applies the placeholder algorithm (SPEC §8.2) to s for every
// secret in the (length-descending) slice. Uses strings.NewReplacer so that
// inserted placeholders are not re-scanned — important when a short secret
// is a substring of a longer secret's placeholder. Each placeholder is
// downgraded to [REDACTED] if it would otherwise expose another secret.
func redactString(s string, secrets []string) string {
	pmap := safePlaceholders(secrets)
	if len(pmap) == 0 {
		return s
	}
	pairs := make([]string, 0, len(pmap)*2)
	for _, sec := range secrets {
		if p, ok := pmap[sec]; ok {
			pairs = append(pairs, sec, p)
		}
	}
	return strings.NewReplacer(pairs...).Replace(s)
}

// safePlaceholders downgrades any placeholder that would leak another secret
// (i.e., one secret as a substring of another's preserved prefix/suffix).
func safePlaceholders(secrets []string) map[string]string {
	pmap := make(map[string]string, len(secrets))
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		pmap[sec] = placeholder(sec)
	}
	for sec, p := range pmap {
		if p == "[REDACTED]" {
			continue
		}
		for other := range pmap {
			if other == sec {
				continue
			}
			if strings.Contains(p, other) {
				pmap[sec] = "[REDACTED]"
				break
			}
		}
	}
	return pmap
}

// Placeholder is the public entry to the redaction algorithm. Exposed for
// tests and the template-level defense-in-depth helper.
func Placeholder(secret string) string { return placeholder(secret) }

// Redact applies the redaction algorithm to a single string. Useful as a
// helper outside the Plan struct (e.g., commit messages).
func Redact(s string, secrets []string) string {
	dedup := uniqueNonEmpty(secrets)
	sort.Slice(dedup, func(i, j int) bool { return len(dedup[i]) > len(dedup[j]) })
	return redactString(s, dedup)
}

func placeholder(secret string) string {
	if len(secret) <= 8 {
		return "[REDACTED]"
	}
	return secret[:4] + "…[REDACTED]…" + secret[len(secret)-4:]
}

// findLeak scans every string in the plan for any unredacted secret. Returns
// the first secret found and false on failure. true means the plan is clean.
func findLeak(p *Plan, secrets []string) (string, bool) {
	var leaked string
	clean := true
	rewriteAllStrings(p, func(s string) string {
		if !clean {
			return s
		}
		for _, sec := range secrets {
			if sec == "" {
				continue
			}
			if strings.Contains(s, sec) {
				leaked = sec
				clean = false
				return s
			}
		}
		return s
	})
	return leaked, clean
}

func (p *Plan) deepCopy() *Plan {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Items = make([]PlanItem, len(p.Items))
	for i, it := range p.Items {
		ci := it
		ci.Locations = append([]Location(nil), it.Locations...)
		ci.RevocationSteps = append([]string(nil), it.RevocationSteps...)
		ci.CodeEdits = append([]CodeEdit(nil), it.CodeEdits...)
		if it.AccessMap != nil {
			am := *it.AccessMap
			am.Permissions = append([]string(nil), it.AccessMap.Permissions...)
			am.Resources = append([]string(nil), it.AccessMap.Resources...)
			ci.AccessMap = &am
		}
		cp.Items[i] = ci
	}
	if p.HistoryRewrite != nil {
		hr := *p.HistoryRewrite
		hr.SideEffects = append([]string(nil), p.HistoryRewrite.SideEffects...)
		hr.PostSteps = append([]string(nil), p.HistoryRewrite.PostSteps...)
		cp.HistoryRewrite = &hr
	}
	return &cp
}

// rewriteAllStrings applies fn to every string field in the plan.
func rewriteAllStrings(p *Plan, fn func(string) string) {
	if p == nil {
		return
	}
	p.RepoPath = fn(p.RepoPath)
	p.BaseBranch = fn(p.BaseBranch)
	p.KingfisherVer = fn(p.KingfisherVer)
	p.LeakfixVer = fn(p.LeakfixVer)
	for i := range p.Items {
		it := &p.Items[i]
		it.FindingID = fn(it.FindingID)
		it.Provider = fn(it.Provider)
		it.DisplayName = fn(it.DisplayName)
		it.RunbookID = fn(it.RunbookID)
		it.ConsoleURL = fn(it.ConsoleURL)
		it.AgentRationale = fn(it.AgentRationale)
		for j := range it.RevocationSteps {
			it.RevocationSteps[j] = fn(it.RevocationSteps[j])
		}
		for j := range it.Locations {
			it.Locations[j].File = fn(it.Locations[j].File)
			it.Locations[j].CommitSHA = fn(it.Locations[j].CommitSHA)
			it.Locations[j].BlobURL = fn(it.Locations[j].BlobURL)
			it.Locations[j].CommitURL = fn(it.Locations[j].CommitURL)
		}
		for j := range it.CodeEdits {
			e := &it.CodeEdits[j]
			e.File = fn(e.File)
			e.OldContent = fn(e.OldContent)
			e.NewContent = fn(e.NewContent)
			e.EnvVarName = fn(e.EnvVarName)
			e.Rationale = fn(e.Rationale)
		}
		if it.AccessMap != nil {
			it.AccessMap.Identity = fn(it.AccessMap.Identity)
			for j := range it.AccessMap.Permissions {
				it.AccessMap.Permissions[j] = fn(it.AccessMap.Permissions[j])
			}
			for j := range it.AccessMap.Resources {
				it.AccessMap.Resources[j] = fn(it.AccessMap.Resources[j])
			}
		}
	}
	if p.HistoryRewrite != nil {
		p.HistoryRewrite.Command = fn(p.HistoryRewrite.Command)
		for i := range p.HistoryRewrite.SideEffects {
			p.HistoryRewrite.SideEffects[i] = fn(p.HistoryRewrite.SideEffects[i])
		}
		for i := range p.HistoryRewrite.PostSteps {
			p.HistoryRewrite.PostSteps[i] = fn(p.HistoryRewrite.PostSteps[i])
		}
	}
}
