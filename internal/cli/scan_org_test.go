package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepoKeyFromFinding_ExtractsOwnerRepo(t *testing.T) {
	f := scanner.Finding{
		Locations: []scanner.Location{{
			File:    "src/main.go",
			Line:    1,
			BlobURL: "https://github.com/leaktk/fake-leaks/blob/abc123/src/main.go#L1",
		}},
	}
	assert.Equal(t, "leaktk/fake-leaks", repoKeyFromFinding(f))
}

func TestRepoKeyFromFinding_FallsBackForUnknown(t *testing.T) {
	f := scanner.Finding{
		Locations: []scanner.Location{{File: "foo.go", Line: 1}},
	}
	assert.Equal(t, "(unknown repository)", repoKeyFromFinding(f))
}

func TestWriteOrgMarkdown_GroupsByRepo(t *testing.T) {
	findings := []scanner.Finding{
		{
			RuleID:    "kingfisher.aws.2",
			Validated: true,
			Locations: []scanner.Location{{
				File:      "config/dev.go",
				Line:      42,
				CommitSHA: "abc1234deadbeef",
				BlobURL:   "https://github.com/anthropics/repo-a/blob/abc1234/config/dev.go#L42",
				CommitURL: "https://github.com/anthropics/repo-a/commit/abc1234",
			}},
		},
		{
			RuleID: "kingfisher.github.2",
			Locations: []scanner.Location{{
				File:    "scripts/release.sh",
				Line:    8,
				BlobURL: "https://github.com/anthropics/repo-b/blob/def5678/scripts/release.sh#L8",
			}},
		},
		{
			RuleID: "kingfisher.openai.2",
			Locations: []scanner.Location{{
				File:    "api/key.go",
				Line:    1,
				BlobURL: "https://github.com/anthropics/repo-a/blob/abc1234/api/key.go#L1",
			}},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, writeOrgMarkdown(&buf, []string{"anthropics"}, findings, scanner.Meta{KingfisherVersion: "1.98.0"}))
	out := buf.String()

	assert.Contains(t, out, "# GitHub org scan: anthropics")
	assert.Contains(t, out, "_kingfisher 1.98.0_")
	assert.Contains(t, out, "**Total findings:** 3")

	// Findings grouped per repo, alphabetically sorted.
	idxA := strings.Index(out, "## anthropics/repo-a")
	idxB := strings.Index(out, "## anthropics/repo-b")
	assert.Greater(t, idxA, -1, "repo-a section present")
	assert.Greater(t, idxB, -1, "repo-b section present")
	assert.Less(t, idxA, idxB, "repo-a sorts before repo-b")

	// repo-a should have 2 findings, repo-b 1.
	assert.Contains(t, out, "## anthropics/repo-a — 2 finding(s)")
	assert.Contains(t, out, "## anthropics/repo-b — 1 finding(s)")

	// Validated marker present, GitHub link rendered.
	assert.Contains(t, out, "validated as live")
	assert.Contains(t, out, "[view on GitHub](https://github.com/anthropics/repo-a/blob/abc1234/config/dev.go#L42)")
	assert.Contains(t, out, "[commit abc1234](https://github.com/anthropics/repo-a/commit/abc1234)")
}
