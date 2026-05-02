package doctor_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/malamsyah/leakfix/internal/doctor"
	"github.com/stretchr/testify/assert"
)

func TestRun_ProducesAllChecks(t *testing.T) {
	rep := doctor.Run(context.Background())
	names := map[string]bool{}
	for _, c := range rep.Checks {
		names[c.Name] = true
	}
	for _, want := range []string{"kingfisher", "git-filter-repo", "gh_or_gh_token", "anthropic_api_key", "go"} {
		assert.True(t, names[want], "expected check %q in report", want)
	}
}

func TestWriteHuman_RendersAllRows(t *testing.T) {
	rep := doctor.Run(context.Background())
	var buf bytes.Buffer
	rep.WriteHuman(&buf)
	out := buf.String()
	assert.True(t, strings.Contains(out, "Go") || strings.Contains(out, "go"))
	assert.True(t, strings.Contains(out, "✓") || strings.Contains(out, "✗"))
}
