package scanner_test

import (
	"context"
	"testing"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestIsRemoteTarget(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"./repo", false},
		{"/abs/path", false},
		{"github.com/leaktk/fake-leaks", true},
		{"https://github.com/leaktk/fake-leaks", true},
		{"http://github.com/leaktk/fake-leaks", true},
		{"git@github.com:leaktk/fake-leaks.git", true},
		{"  github.com/owner/repo  ", true}, // trims whitespace
		{"", false},
		{"gitlab.com/owner/repo", false}, // GitLab not handled in v1
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, scanner.IsRemoteTarget(tc.target), "target=%q", tc.target)
	}
}

// ScanGitHub must reject empty input — both Organizations and Users empty.
func TestScanGitHub_RequiresOrgOrUser(t *testing.T) {
	s := scanner.New()
	_, _, err := s.ScanGitHub(context.Background(), scanner.GitHubScanOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "organization")
}
