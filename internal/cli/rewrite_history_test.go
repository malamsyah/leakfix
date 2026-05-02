package cli

import (
	"strings"
	"testing"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildHistoryRewrite_EmitsCommandAndSideEffects(t *testing.T) {
	findings := []scanner.Finding{
		{ID: "f1", Locations: []scanner.Location{{File: "a.go", Line: 1}}},
		{ID: "f2", Locations: []scanner.Location{{File: "scripts/release.sh", Line: 8}}},
	}
	hr := buildHistoryRewrite(findings)
	require.NotNil(t, hr)

	assert.Contains(t, hr.Command, "git filter-repo")
	assert.True(t, strings.Contains(hr.Command, "a.go") || strings.Contains(hr.Command, "scripts/release.sh"))
	assert.NotEmpty(t, hr.SideEffects)
	assert.NotEmpty(t, hr.PostSteps)

	// The emitter must NOT include any execution step that auto force-pushes.
	for _, s := range hr.PostSteps {
		assert.NotContains(t, strings.ToLower(s), "auto", "history-rewrite must never imply auto-execution")
	}
}

func TestBuildHistoryRewrite_NilOnNoFindings(t *testing.T) {
	assert.Nil(t, buildHistoryRewrite(nil))
}
