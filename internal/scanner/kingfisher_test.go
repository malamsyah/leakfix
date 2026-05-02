package scanner_test

import (
	"testing"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFindings_DeduplicatesBySecretHash(t *testing.T) {
	raw := []byte(`{
	  "findings": [
	    {"id": "1", "rule_id": "kingfisher.aws.access_key", "secret": "AKIAIOSFODNN7EXAMPLE", "secret_hash": "h1", "validated": true, "path": "a.go", "line": 10},
	    {"id": "2", "rule_id": "kingfisher.aws.access_key", "secret": "AKIAIOSFODNN7EXAMPLE", "secret_hash": "h1", "validated": false, "path": "b.go", "line": 20},
	    {"id": "3", "rule_id": "kingfisher.github.pat_classic", "secret": "ghp_abcd1234", "secret_hash": "h2", "path": "c.sh", "line": 5}
	  ]
	}`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	aws := findings[0]
	assert.Equal(t, "h1", aws.SecretHash)
	assert.True(t, aws.Validated, "validated bit must propagate from any of the dup findings")
	assert.Len(t, aws.Locations, 2, "expected one Finding with two Locations")

	gh := findings[1]
	assert.Equal(t, "h2", gh.SecretHash)
	assert.Len(t, gh.Locations, 1)
}

func TestParseFindings_TolerantToBareArray(t *testing.T) {
	raw := []byte(`[{"rule_id":"x","secret":"abc","secret_hash":"h","path":"a","line":1}]`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
}

func TestParseFindings_HashFallback(t *testing.T) {
	// no secret_hash, no secret — uses rule:path:line as fallback id
	raw := []byte(`[{"rule_id":"r","path":"a","line":1}]`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.NotEmpty(t, findings[0].SecretHash)
}

func TestParseFindings_EmptyInput(t *testing.T) {
	findings, err := scanner.ParseFindings([]byte(""))
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// Kingfisher 1.x emits a summary with `findings: <count>` and a
// `findings_by_rule` array. Verify we synthesize when findings>0.
func TestParseFindings_KingfisherSummarySchema(t *testing.T) {
	raw := []byte(`{
		"findings": 3,
		"successful_validations": 0,
		"failed_validations": 0,
		"skipped_validations": 0,
		"rules_applied": 916,
		"blobs_scanned": 37,
		"bytes_scanned": 26799,
		"scan_duration": 0.27,
		"scan_date": "2026-05-01T22:39:54+09:00",
		"kingfisher": {"version_used": "1.98.0"},
		"findings_by_rule": [["AWS Access Key ID", 2], ["GitHub PAT", 1]]
	}`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 3, "two AWS + one GitHub PAT = three synthetic findings")

	rules := map[string]int{}
	for _, f := range findings {
		rules[f.RuleID]++
	}
	assert.Equal(t, 2, rules["kingfisher.summary.aws_access_key_id"])
	assert.Equal(t, 1, rules["kingfisher.summary.github_pat"])
	assert.Contains(t, findings[0].Locations[0].File, "detail unavailable")
}

// findings: 0 means kingfisher filtered everything as sub-threshold; we
// must NOT synthesize findings_by_rule entries.
func TestParseFindings_KingfisherSummary_ZeroDisplayable(t *testing.T) {
	raw := []byte(`{"findings": 0, "findings_by_rule": [["Twitter Consumer Key", 1]]}`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	assert.Empty(t, findings, "sub-threshold matches must not be promoted to findings")
}

func TestParseFindings_KingfisherSummary_NoFindings(t *testing.T) {
	raw := []byte(`{"findings": 0, "findings_by_rule": []}`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// Kingfisher 1.x detail schema: two concatenated JSON objects, the first
// holding nested {rule, finding} entries and the second holding the summary.
// Verify we extract real per-finding data: rule_id, secret, file, line,
// validation status, fingerprint.
func TestParseFindings_Kingfisher1xDetailSchema(t *testing.T) {
	raw := []byte(`{
		"findings": [
			{
				"rule": {"name": "AWS Secret Access Key", "id": "kingfisher.aws.2"},
				"finding": {
					"snippet": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1",
					"fingerprint": "fp-aws-1",
					"confidence": "high",
					"validation": {"status": "Active", "response": "ok"},
					"language": "Go",
					"line": 42,
					"path": "config/dev.go",
					"git_metadata": {
						"repository_url": "https://github.com/x/y",
						"commit": {"id": "abc1234", "url": "https://github.com/x/y/commit/abc1234"},
						"file": {"path": "config/dev.go", "url": "https://github.com/x/y/blob/abc1234/config/dev.go#L42"}
					}
				}
			},
			{
				"rule": {"name": "GitHub PAT", "id": "kingfisher.github.2"},
				"finding": {
					"snippet": "ghp_pretendtoken1234567890aaaaaaaaaaaaaaaa",
					"fingerprint": "fp-gh-1",
					"confidence": "high",
					"validation": {"status": "Not Attempted"},
					"line": 8,
					"path": "scripts/release.sh"
				}
			}
		],
		"metadata": {"target": "/repo"}
	}
	{"findings": 2, "findings_by_rule": [["AWS Secret Access Key", 1], ["GitHub PAT", 1]]}`)

	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 2)

	aws := findings[0]
	assert.Equal(t, "kingfisher.aws.2", aws.RuleID)
	assert.Equal(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1", aws.Secret)
	assert.True(t, aws.Validated, `validation.status "Active" -> Validated true`)
	assert.Equal(t, "fp-aws-1", aws.SecretHash)
	require.Len(t, aws.Locations, 1)
	assert.Equal(t, "config/dev.go", aws.Locations[0].File)
	assert.Equal(t, 42, aws.Locations[0].Line)
	assert.Equal(t, "abc1234", aws.Locations[0].CommitSHA)
	assert.Equal(t, "https://github.com/x/y/blob/abc1234/config/dev.go#L42", aws.Locations[0].BlobURL)
	assert.Equal(t, "https://github.com/x/y/commit/abc1234", aws.Locations[0].CommitURL)

	gh := findings[1]
	assert.Equal(t, "kingfisher.github.2", gh.RuleID)
	assert.False(t, gh.Validated, `"Not Attempted" -> Validated false`)
	assert.Equal(t, "scripts/release.sh", gh.Locations[0].File)
	assert.Equal(t, 8, gh.Locations[0].Line)
}

// Kingfisher 1.x's remote-clone path (`kingfisher scan github.com/owner/repo`)
// produces malformed URLs that embed the local tmpdir. We must detect this and
// rebuild the URL from repository_url + commit id + file path.
func TestParseFindings_RebuildsMalformedRemoteURLs(t *testing.T) {
	raw := []byte(`{
		"findings": [
			{
				"rule": {"id": "kingfisher.aws.2"},
				"finding": {
					"snippet": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1",
					"fingerprint": "fp-1",
					"line": 5,
					"path": "config/dev.go",
					"git_metadata": {
						"repository_url": "https://github.com/leaktk/fake-leaks",
						"commit": {"id": "abc1234", "url": "/var/folders/.../tmpXXX/leaktk_fake-leaks/commit/abc1234"},
						"file":   {"path": "config/dev.go", "url": "/var/folders/.../tmpXXX/leaktk_fake-leaks/blob/abc1234/config/dev.go#L5"}
					}
				}
			}
		]
	}`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Len(t, findings[0].Locations, 1)
	loc := findings[0].Locations[0]
	assert.Equal(t, "https://github.com/leaktk/fake-leaks/blob/abc1234/config/dev.go#L5", loc.BlobURL)
	assert.Equal(t, "https://github.com/leaktk/fake-leaks/commit/abc1234", loc.CommitURL)
}

// When the same secret appears in multiple files, kingfisher 1.x emits one
// finding per location (different snippets/fingerprints). Verify our
// post-parse dedup keeps each as a separate location-list entry when their
// fingerprints differ — and merges them when fingerprints match.
func TestParseFindings_Kingfisher1xMultiLocation(t *testing.T) {
	raw := []byte(`{
		"findings": [
			{"rule":{"id":"kingfisher.aws.2"},"finding":{"snippet":"AKIAEXAMPLE","fingerprint":"same","line":1,"path":"a.go"}},
			{"rule":{"id":"kingfisher.aws.2"},"finding":{"snippet":"AKIAEXAMPLE","fingerprint":"same","line":2,"path":"b.go"}}
		]
	}`)
	findings, err := scanner.ParseFindings(raw)
	require.NoError(t, err)
	require.Len(t, findings, 1, "same fingerprint -> one Finding")
	assert.Len(t, findings[0].Locations, 2, "two locations preserved")
}

func TestCheckKingfisherVersion(t *testing.T) {
	cases := []struct {
		v        string
		expected bool
	}{
		{"0.6.0", true},
		{"0.6.2", true},
		{"0.9.99", true},
		{"1.0.0", true},
		{"1.98.0", true}, // current upstream
		{"0.5.9", false},
		{"2.0.0", false}, // exclusive upper bound
		{"kingfisher 0.7.1 (build abc)", true},
	}
	for _, tc := range cases {
		t.Run(tc.v, func(t *testing.T) {
			ok, err := scanner.CheckKingfisherVersion(tc.v)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, ok)
		})
	}
}

func TestSecretValues_OmitsEmpty(t *testing.T) {
	got := scanner.SecretValues([]scanner.Finding{
		{Secret: "a"},
		{Secret: ""},
		{Secret: "b"},
	})
	assert.Equal(t, []string{"a", "b"}, got)
}
