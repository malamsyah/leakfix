package scanner_test

import (
	"testing"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestApplyFilters_DropsTestPathsByDefault(t *testing.T) {
	in := []scanner.Finding{
		{ID: "real", Secret: "ghp_realtokenAbcDeFgHiJkLmNoPqRsTuVwXyZ",
			Locations: []scanner.Location{{File: "scripts/release.sh", Line: 8}}},
		{ID: "fixture", Secret: "ghp_anotherRealValAbCdEfGhIjKlMnOpQrStUv",
			Locations: []scanner.Location{{File: "testdata/fixtures/aws-leak/config.go", Line: 1}}},
		{ID: "test_go", Secret: "ghp_oneMoreRealKAbCdEfGhIjKlMnOpQrStUcccc",
			Locations: []scanner.Location{{File: "internal/foo/bar_test.go", Line: 12}}},
		{ID: "fixtures_dir", Secret: "ghp_yetAnotherKeyAbCdEfGhIjKlMnOpQrSdddd",
			Locations: []scanner.Location{{File: "spec/fixtures/data.json", Line: 1}}},
	}
	res := scanner.ApplyFilters(in, scanner.FilterOptions{})
	assert.Len(t, res.Kept, 1, "only the real finding should remain")
	assert.Equal(t, "real", res.Kept[0].ID)
	assert.Equal(t, 3, res.DroppedTestPath)
}

func TestApplyFilters_DropsDummySecretsByDefault(t *testing.T) {
	in := []scanner.Finding{
		{ID: "real", Secret: "ghp_realtokenAbcDeFgHiJkLmNoPqRsTuVwXyZ",
			Locations: []scanner.Location{{File: "main.go", Line: 1}}},
		{ID: "example", Secret: "AKIAIOSFODNN7EXAMPLE",
			Locations: []scanner.Location{{File: "main.go", Line: 2}}},
		{ID: "fake", Secret: "ghp_FAKE_FIXTURE_NOT_A_REAL_TOKEN_xx",
			Locations: []scanner.Location{{File: "main.go", Line: 3}}},
		{ID: "placeholder", Secret: "<your-key-here>",
			Locations: []scanner.Location{{File: "main.go", Line: 4}}},
	}
	res := scanner.ApplyFilters(in, scanner.FilterOptions{})
	assert.Len(t, res.Kept, 1)
	assert.Equal(t, "real", res.Kept[0].ID)
}

func TestApplyFilters_IncludeTestFilesFlag(t *testing.T) {
	in := []scanner.Finding{
		{ID: "fixture", Secret: "ghp_realtokenAbCdEfGhIjKlMnOpQrStUv9998",
			Locations: []scanner.Location{{File: "testdata/fixtures/aws-leak/config.go", Line: 1}}},
	}
	res := scanner.ApplyFilters(in, scanner.FilterOptions{IncludeTestFiles: true})
	assert.Len(t, res.Kept, 1)
	assert.Equal(t, 0, res.DroppedTestPath)
}

func TestApplyFilters_IncludeDummyFlag(t *testing.T) {
	in := []scanner.Finding{
		{ID: "example", Secret: "AKIAIOSFODNN7EXAMPLE",
			Locations: []scanner.Location{{File: "main.go", Line: 2}}},
	}
	res := scanner.ApplyFilters(in, scanner.FilterOptions{IncludeDummySecrets: true})
	assert.Len(t, res.Kept, 1)
}

// A finding with one test-path location and one real location should keep the
// real location and drop the test-path one.
func TestApplyFilters_PartialTestLocationsKeepNonTest(t *testing.T) {
	f := scanner.Finding{
		ID:     "mixed",
		Secret: "ghp_realtokenAbCdEfGhIjKlMnOpQrStUv8887",
		Locations: []scanner.Location{
			{File: "testdata/fixtures/leak.go", Line: 1},
			{File: "src/handler.go", Line: 42},
		},
	}
	res := scanner.ApplyFilters([]scanner.Finding{f}, scanner.FilterOptions{})
	require := assert.New(t)
	require.Len(res.Kept, 1)
	require.Len(res.Kept[0].Locations, 1)
	require.Equal("src/handler.go", res.Kept[0].Locations[0].File)
}

func TestApplyFilters_DropsVendoredPaths(t *testing.T) {
	in := []scanner.Finding{
		{ID: "real", Secret: "ghp_realtokenAbCdEfGhIjKlMnOp",
			Locations: []scanner.Location{{File: "src/main.go", Line: 1}}},
		{ID: "vendored", Secret: "ghp_vendoredKeyAbCdEfGhIjKlMn",
			Locations: []scanner.Location{{File: "vendor/github.com/lib/pq/conn.go", Line: 12}}},
		{ID: "node", Secret: "ghp_nodeKeyAbCdEfGhIjKlMnOpQr",
			Locations: []scanner.Location{{File: "node_modules/axios/dist/index.js", Line: 100}}},
		{ID: "venv", Secret: "ghp_venvKeyAbCdEfGhIjKlMnOpQr",
			Locations: []scanner.Location{{File: ".venv/lib/python3.12/site-packages/foo.py", Line: 1}}},
	}
	res := scanner.ApplyFilters(in, scanner.FilterOptions{IncludeTestFiles: true, IncludeDummySecrets: true})
	if assert.Len(t, res.Kept, 1, "only the non-vendored finding should remain") {
		assert.Equal(t, "real", res.Kept[0].ID)
	}
	assert.Equal(t, 3, res.DroppedVendored)
}

// Vendored paths must be dropped even when --no-filter / --include-test-files
// would otherwise allow them — this filter is always on.
func TestApplyFilters_VendoredAlwaysOnRegardlessOfFlags(t *testing.T) {
	in := []scanner.Finding{
		{ID: "v", Secret: "ghp_vendoredKeyAbCdEfGhIjKlMn",
			Locations: []scanner.Location{{File: "vendor/lib/foo.go", Line: 1}}},
	}
	res := scanner.ApplyFilters(in, scanner.FilterOptions{IncludeTestFiles: true, IncludeDummySecrets: true})
	assert.Empty(t, res.Kept, "vendored filter is unconditional")
	assert.Equal(t, 1, res.DroppedVendored)
}

func TestIsVendoredPath_Cases(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"vendor/github.com/foo/bar.go", true},
		{"./vendor/github.com/foo/bar.go", true},
		{"src/handler.go", false},
		{"node_modules/axios/index.js", true},
		{"frontend/node_modules/lodash/index.js", true},
		{".venv/lib/python3.12/site-packages/foo.py", true},
		{"venv/Lib/foo.py", true},
		{"src/__pycache__/main.cpython-312.pyc", true},
		{".git/config", true}, // ephemeral CI tokens live here
		{".git/refs/remotes/origin/main", true},
		{"./.git/config", true},
		{"build/output.bin", false}, // build/ intentionally NOT in the list
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, scanner.IsVendoredPath(tc.path), "path=%s", tc.path)
	}
}

func TestIsTestPath_Cases(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"testdata/fixtures/x.go", true},
		{"./testdata/x.go", true},
		{"internal/foo_test.go", true},
		{"src/handler.go", false},
		{"src/components/Button.test.tsx", true},
		{"src/components/Button.spec.ts", true},
		{"docs/examples/aws-key.txt", true},
		{"examples/openai/main.py", true},
		{"__tests__/login.js", true},
		{"pki/invalid/dummy.key", true},
		{"path/to/dummy_data.go", true},
		{"src/dummy.go", true},
		{"src/main.go", false},
	}
	for _, tc := range cases {
		got := scanner.IsTestPath(tc.path)
		assert.Equal(t, tc.want, got, "path=%s", tc.path)
	}
}

func TestIsDummySecret_Cases(t *testing.T) {
	cases := []struct {
		secret string
		want   bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", true},
		{"ghp_FAKE_token_yyy", true},
		{"<your-api-key-here>", true},
		{"DUMMY_SECRET_VALUE", true},
		{"placeholder-replace-me", true},
		{"sk-XXXXXXXXXXXXXXXXXXXXXXXXX", true},
		{"sk-ant-RealLookingApiKeyAbCdEfGhIjKlMn", false},
		{"", false},
		// localhost / docker-compose URIs are local-dev creds
		{"postgres://postgres:mlink@localhost:6432/mlink?sslmode=disable", true},
		{"mysql://root:secret@127.0.0.1:3306/app", true},
		{"redis://:devpass@redis:6379/0", true},
		{"mongodb://admin:admin@host.docker.internal:27017", true},
		{"postgres://user:pw@db:5432/app", true},
		// Real-looking remote DBs must NOT match
		{"postgres://user:pw@prod-db.us-east-1.rds.amazonaws.com:5432/app", false},
		{"mysql://app:realprodpass@10.0.5.20:3306/billing", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, scanner.IsDummySecret(tc.secret), "secret=%q", tc.secret)
	}
}

func TestIsLocalDevCredential_RequiresURIScheme(t *testing.T) {
	// A bare mention of "localhost" in plain text must NOT trip the check —
	// only URIs with embedded credentials should be treated as local-dev.
	assert.False(t, scanner.IsLocalDevCredential("see localhost docs at https://example.com"))
	assert.False(t, scanner.IsLocalDevCredential("localhost"))
	assert.True(t, scanner.IsLocalDevCredential("postgres://postgres:secret@localhost:5432/db"))
}
