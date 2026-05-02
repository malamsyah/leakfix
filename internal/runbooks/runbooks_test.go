package runbooks_test

import (
	"testing"

	"github.com/malamsyah/leakfix/internal/runbooks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_AllRequiredRunbooksPresent(t *testing.T) {
	reg, err := runbooks.Load()
	require.NoError(t, err)

	expected := []string{
		"_generic",
		"aws_iam_access_key",
		"github_pat",
		"stripe_api_key",
		"slack_webhook",
		"openai_api_key",
		"anthropic_api_key",
	}
	for _, id := range expected {
		_, ok := reg.ByID(id)
		assert.True(t, ok, "expected runbook %q to load", id)
	}
}

func TestLoad_NoDuplicateIDs(t *testing.T) {
	// Load() errors on dup; just calling it is enough.
	_, err := runbooks.Load()
	require.NoError(t, err)
}

func TestMatch_PrefixMatching(t *testing.T) {
	reg, err := runbooks.Load()
	require.NoError(t, err)

	cases := []struct {
		ruleID   string
		expected string
	}{
		// kingfisher 0.x rule-ID style
		{"kingfisher.aws.access_key", "aws_iam_access_key"},
		{"kingfisher.aws.access_key.v2", "aws_iam_access_key"},
		{"kingfisher.github.pat_classic", "github_pat"},
		{"kingfisher.github.pat", "github_pat"},
		{"kingfisher.github.fine_grained_pat", "github_pat"},
		{"kingfisher.stripe.live", "stripe_api_key"},
		{"kingfisher.stripe.test", "stripe_api_key"},
		{"kingfisher.openai.user", "openai_api_key"},
		{"kingfisher.anthropic.api_key", "anthropic_api_key"},
		{"kingfisher.slack.webhook", "slack_webhook"},
		// kingfisher 1.x rule-ID style: kingfisher.<provider>.<n>
		{"kingfisher.aws.2", "aws_iam_access_key"},
		{"kingfisher.github.2", "github_pat"},
		{"kingfisher.github.5", "github_pat"},
		{"kingfisher.stripe.2", "stripe_api_key"},
		{"kingfisher.openai.2", "openai_api_key"},
		{"kingfisher.slack.4", "slack_webhook"},
		{"kingfisher.slack.1", "slack_webhook"},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			rb, ok := reg.Match(tc.ruleID)
			assert.True(t, ok, "expected match")
			assert.Equal(t, tc.expected, rb.ID)
		})
	}
}

func TestMatch_FallsBackToGeneric(t *testing.T) {
	reg, err := runbooks.Load()
	require.NoError(t, err)

	rb, ok := reg.Match("kingfisher.unknown.thing")
	assert.False(t, ok, "Match returns false on no-match (but still returns generic)")
	assert.Equal(t, "_generic", rb.ID)
}

func TestProviders_ExcludesGeneric(t *testing.T) {
	reg, err := runbooks.Load()
	require.NoError(t, err)

	for _, p := range reg.Providers() {
		assert.NotEqual(t, "_generic", p)
	}
}
