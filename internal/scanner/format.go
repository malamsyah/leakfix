package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/malamsyah/leakfix/internal/plan"
)

// RedactedPreview returns a one-line, redacted preview of a finding's
// secret value safe to embed in any user-facing output. Multi-line
// snippets (e.g. PEM blocks) are collapsed to the first non-empty line so
// the report stays tabular.
func RedactedPreview(secret string) string {
	if secret == "" {
		return ""
	}
	first := secret
	if i := strings.IndexAny(secret, "\r\n"); i >= 0 {
		first = secret[:i]
	}
	first = strings.TrimSpace(first)
	if first == "" {
		first = strings.TrimSpace(secret)
	}
	return plan.Placeholder(first)
}

// WriteMarkdown writes a human-readable scan report to w. Secrets are
// redacted before rendering.
func WriteMarkdown(w io.Writer, repoPath string, findings []Finding, meta Meta) error {
	secrets := SecretValues(findings)
	red := func(s string) string { return plan.Redact(s, secrets) }

	if _, err := fmt.Fprintf(w, "# Scan report for %s\n\n", repoPath); err != nil {
		return err
	}
	if meta.KingfisherVersion != "" {
		fmt.Fprintf(w, "_kingfisher %s_\n\n", meta.KingfisherVersion)
	}
	fmt.Fprintf(w, "**Findings:** %d\n\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(w, "## %d. %s\n", i+1, red(f.RuleID))
		fmt.Fprintf(w, "- finding id: `%s`\n", red(f.ID))
		if preview := RedactedPreview(f.Secret); preview != "" {
			fmt.Fprintf(w, "- redacted value: `%s`\n", preview)
		}
		if f.Validated {
			fmt.Fprintln(w, "- validated: yes")
		}
		fmt.Fprintln(w, "- locations:")
		for _, loc := range f.Locations {
			fmt.Fprintf(w, "  - `%s:%d`", loc.File, loc.Line)
			if loc.CommitSHA != "" {
				short := loc.CommitSHA
				if len(short) > 7 {
					short = short[:7]
				}
				if loc.CommitURL != "" {
					fmt.Fprintf(w, " @ [%s](%s)", short, loc.CommitURL)
				} else {
					fmt.Fprintf(w, " @ %s", short)
				}
			}
			if loc.BlobURL != "" {
				fmt.Fprintf(w, " — [view on GitHub](%s)", loc.BlobURL)
			}
			fmt.Fprintln(w)
		}
		if f.AccessMap != nil && f.AccessMap.Identity != "" {
			fmt.Fprintf(w, "- access map: %s — permissions: %v\n", red(f.AccessMap.Identity), f.AccessMap.Permissions)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// WriteSARIF emits a minimal SARIF 2.1.0 report. We don't attempt full
// SARIF compliance; the goal is enough fields for GitHub code-scanning.
func WriteSARIF(w io.Writer, findings []Finding) error {
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   map[string]any  `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}
	type sarifRun struct {
		Tool struct {
			Driver map[string]any `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		for _, loc := range f.Locations {
			r := sarifResult{
				RuleID:  f.RuleID,
				Level:   "error",
				Message: map[string]any{"text": "Secret detected by Kingfisher"},
			}
			var sl sarifLocation
			sl.PhysicalLocation.ArtifactLocation.URI = loc.File
			sl.PhysicalLocation.Region.StartLine = loc.Line
			r.Locations = append(r.Locations, sl)
			results = append(results, r)
		}
	}

	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: struct {
				Driver map[string]any `json:"driver"`
			}{Driver: map[string]any{"name": "kingfisher", "informationUri": "https://github.com/mongodb/kingfisher"}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
