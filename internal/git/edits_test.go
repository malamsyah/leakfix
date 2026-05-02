package git_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/malamsyah/leakfix/internal/git"
	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
}

func TestApplyPlanEdits_Success(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `key := "AKIAIOSFODNN7EXAMPLE"`)

	p := &plan.Plan{Items: []plan.PlanItem{{
		FindingID: "f1", RunbookID: "x", Severity: plan.SeverityHigh,
		Locations: []plan.Location{{File: "config.go", Line: 1}},
		CodeEdits: []plan.CodeEdit{{
			File:       "config.go",
			OldContent: `"AKIAIOSFODNN7EXAMPLE"`,
			NewContent: `os.Getenv("AWS_ACCESS_KEY_ID")`,
			EnvVarName: "AWS_ACCESS_KEY_ID",
		}},
	}}}

	failures, err := git.ApplyPlanEdits(dir, p)
	require.NoError(t, err)
	assert.Empty(t, failures)

	out, _ := os.ReadFile(filepath.Join(dir, "config.go"))
	assert.Equal(t, `key := os.Getenv("AWS_ACCESS_KEY_ID")`, string(out))
}

func TestApplyPlanEdits_FileChangedSinceScan(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.go", `// the file was edited since scan`)

	p := &plan.Plan{Items: []plan.PlanItem{{
		FindingID: "f1", RunbookID: "x", Severity: plan.SeverityHigh,
		Locations: []plan.Location{{File: "config.go", Line: 1}},
		CodeEdits: []plan.CodeEdit{{
			File:       "config.go",
			OldContent: `"NOT_PRESENT"`,
			NewContent: `os.Getenv("X")`,
			EnvVarName: "X",
		}},
	}}}
	failures, err := git.ApplyPlanEdits(dir, p)
	require.NoError(t, err)
	require.Len(t, failures, 1, "missing find string should produce one failure, not abort")
	assert.Contains(t, failures[0].Reason, "old_content not present")
}

func TestApplyPlanEdits_AmbiguousMatch(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "x.go", `a = "secret"; b = "secret"`)

	p := &plan.Plan{Items: []plan.PlanItem{{
		FindingID: "f1", RunbookID: "x", Severity: plan.SeverityHigh,
		Locations: []plan.Location{{File: "x.go", Line: 1}},
		CodeEdits: []plan.CodeEdit{{
			File:       "x.go",
			OldContent: `"secret"`,
			NewContent: `os.Getenv("X")`,
			EnvVarName: "X",
		}},
	}}}
	failures, err := git.ApplyPlanEdits(dir, p)
	require.NoError(t, err)
	require.Len(t, failures, 1)
	assert.Contains(t, failures[0].Reason, "ambiguous")
}
