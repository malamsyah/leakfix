package runbooks

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var bundled embed.FS

// Runbook is the loaded representation of a YAML runbook (SPEC §7).
type Runbook struct {
	ID                          string     `yaml:"id"`
	DisplayName                 string     `yaml:"display_name"`
	KingfisherRules             []string   `yaml:"kingfisher_rules"`
	SeverityDefault             string     `yaml:"severity_default"`
	Revocation                  Revocation `yaml:"revocation"`
	ReplacementPattern          string     `yaml:"replacement_pattern"`
	EnvVarSuggestedName         string     `yaml:"env_var_suggested_name"`
	SecretManagerRecommendation []string   `yaml:"secret_manager_recommendation"`
	Notes                       string     `yaml:"notes"`
	Raw                         []byte     `yaml:"-"`
}

type Revocation struct {
	ConsoleURL string   `yaml:"console_url"`
	APICommand string   `yaml:"api_command"`
	Steps      []string `yaml:"steps"`
}

// GenericID is the fallback runbook ID used when no provider rule matches.
const GenericID = "_generic"

// Registry holds the loaded runbooks.
type Registry struct {
	byID map[string]*Runbook
}

// Load parses every embedded YAML and returns a populated Registry.
func Load() (*Registry, error) {
	entries, err := fs.ReadDir(bundled, "data")
	if err != nil {
		return nil, fmt.Errorf("read data dir: %w", err)
	}

	reg := &Registry{byID: make(map[string]*Runbook, len(entries))}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := fs.ReadFile(bundled, "data/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var rb Runbook
		if err := yaml.Unmarshal(raw, &rb); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		rb.Raw = raw
		if err := validate(&rb); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if _, dup := reg.byID[rb.ID]; dup {
			return nil, fmt.Errorf("duplicate runbook id %q", rb.ID)
		}
		reg.byID[rb.ID] = &rb
	}

	if _, ok := reg.byID[GenericID]; !ok {
		return nil, fmt.Errorf("required fallback runbook %q is missing", GenericID)
	}
	return reg, nil
}

func validate(rb *Runbook) error {
	if rb.ID == "" {
		return fmt.Errorf("id is required")
	}
	if rb.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	if rb.SeverityDefault == "" {
		return fmt.Errorf("severity_default is required")
	}
	if len(rb.Revocation.Steps) == 0 {
		return fmt.Errorf("revocation.steps must be non-empty")
	}
	if rb.ReplacementPattern == "" {
		return fmt.Errorf("replacement_pattern is required")
	}
	return nil
}

// ByID returns the runbook for the given id (or false if not present).
func (r *Registry) ByID(id string) (*Runbook, bool) {
	rb, ok := r.byID[id]
	return rb, ok
}

// Match returns the runbook whose kingfisher_rules prefix-match ruleID, or
// the generic fallback if no match is found. SPEC §7.3: prefix match,
// never exact match; never error on rule-ID mismatch.
func (r *Registry) Match(ruleID string) (*Runbook, bool) {
	if ruleID != "" {
		for _, rb := range r.byID {
			if rb.ID == GenericID {
				continue
			}
			for _, prefix := range rb.KingfisherRules {
				if prefix != "" && strings.HasPrefix(ruleID, prefix) {
					return rb, true
				}
			}
		}
	}
	return r.byID[GenericID], false
}

// All returns every loaded runbook, sorted by id.
func (r *Registry) All() []*Runbook {
	out := make([]*Runbook, 0, len(r.byID))
	for _, rb := range r.byID {
		out = append(out, rb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Providers returns the non-generic runbook IDs (for the agent's `list_providers` tool).
func (r *Registry) Providers() []string {
	out := []string{}
	for id := range r.byID {
		if id != GenericID {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
