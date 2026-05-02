package scanner

import (
	"path/filepath"
	"strings"
)

// FilterOptions controls which findings are dropped before they reach the
// agent / plan / output. Defaults are conservative: skip obvious test
// fixtures and clearly-fake credentials. Set IncludeTestFiles or
// IncludeDummySecrets to surface them anyway.
type FilterOptions struct {
	IncludeTestFiles    bool
	IncludeDummySecrets bool
}

// DefaultFilterOptions returns the default filter (everything on).
func DefaultFilterOptions() FilterOptions {
	return FilterOptions{}
}

// FilterResult is the outcome of applying filters.
type FilterResult struct {
	Kept              []Finding
	DroppedTestPath   int // dropped because the path looks like a test fixture
	DroppedDummyValue int // dropped because the secret looks like an example/placeholder
	DroppedVendored   int // dropped because the path is vendored / third-party
}

// ApplyFilters drops findings the user almost certainly doesn't want to act
// on (test fixtures, example/dummy strings, vendored third-party code).
// Test/dummy filters can be overridden via FilterOptions; the vendored-path
// filter is always on — leakfix is not a tool for remediating other people's
// code.
func ApplyFilters(findings []Finding, opts FilterOptions) FilterResult {
	var res FilterResult
	res.Kept = make([]Finding, 0, len(findings))
	for _, f := range findings {
		// Vendored-path filter (always on).
		nonVendored := keepNonVendoredLocations(f.Locations)
		if len(nonVendored) == 0 {
			res.DroppedVendored++
			continue
		}
		f.Locations = nonVendored

		if !opts.IncludeDummySecrets && IsDummySecret(f.Secret) {
			res.DroppedDummyValue++
			continue
		}
		if !opts.IncludeTestFiles {
			kept := keepNonTestLocations(f.Locations)
			if len(kept) == 0 {
				res.DroppedTestPath++
				continue
			}
			f.Locations = kept
		}
		res.Kept = append(res.Kept, f)
	}
	return res
}

func keepNonVendoredLocations(locs []Location) []Location {
	out := make([]Location, 0, len(locs))
	for _, l := range locs {
		if !IsVendoredPath(l.File) {
			out = append(out, l)
		}
	}
	return out
}

// keepNonTestLocations strips locations whose path looks like a test fixture.
// If every location is in a test path, the finding is dropped entirely.
func keepNonTestLocations(locs []Location) []Location {
	out := make([]Location, 0, len(locs))
	for _, l := range locs {
		if !IsTestPath(l.File) {
			out = append(out, l)
		}
	}
	return out
}

// vendoredPathSegments are directory names that hold third-party code,
// build artefacts, or runtime metadata that leakfix should never scan.
// Findings inside these paths are not leakfix's job to remediate — they
// belong to upstream dependencies, ephemeral build outputs, or
// runtime-managed state (e.g., GitHub Actions writes a short-lived token
// into .git/config that kingfisher would otherwise flag every CI run).
// Match is case-insensitive.
var vendoredPathSegments = []string{
	".git",
	"vendor",
	"node_modules",
	".venv",
	"venv",
	"__pycache__",
	".tox",
	".gradle",
	".bundle",
	"bower_components",
	"jspm_packages",
}

// IsVendoredPath returns true when path lives inside a known third-party /
// dependency / build-output directory.
func IsVendoredPath(path string) bool {
	if path == "" {
		return false
	}
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	for _, seg := range vendoredPathSegments {
		segLower := strings.ToLower(seg)
		if strings.HasPrefix(clean, segLower+"/") || strings.Contains(clean, "/"+segLower+"/") {
			return true
		}
	}
	return false
}

// testPathSegments are directory names that strongly imply test fixtures.
// Match is case-insensitive; both leading-slash and middle-of-path matches
// count.
var testPathSegments = []string{
	"testdata",
	"__tests__",
	"__test__",
	"__mocks__",
	"__fixtures__",
	"fixtures",
	"examples",
	"example",
	"docs/examples",
	"sample",
	"samples",
	"mocks",
	"spec/fixtures",
}

// testFileSuffixes are filename patterns that imply per-file test code.
var testFileSuffixes = []string{
	"_test.go",
	".test.ts",
	".test.tsx",
	".test.js",
	".test.jsx",
	".test.py",
	".spec.ts",
	".spec.tsx",
	".spec.js",
	".spec.jsx",
	".spec.py",
	"_spec.rb",
	"test.rb",
}

// testFilenameContains matches files whose basename contains a test signal.
var testFilenameContains = []string{
	"dummy",
	"example",
	"fixture",
	"placeholder",
	"sample",
	"fake",
}

// IsTestPath returns true when path almost certainly belongs to a test fixture.
func IsTestPath(path string) bool {
	if path == "" {
		return false
	}
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	parts := strings.Split(clean, "/")

	for _, seg := range testPathSegments {
		segLower := strings.ToLower(seg)
		if strings.Contains(segLower, "/") {
			if strings.Contains(clean, "/"+segLower+"/") || strings.HasPrefix(clean, segLower+"/") {
				return true
			}
			continue
		}
		for _, p := range parts {
			if p == segLower {
				return true
			}
		}
	}

	base := strings.ToLower(filepath.Base(clean))
	for _, suf := range testFileSuffixes {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	for _, kw := range testFilenameContains {
		if strings.Contains(base, kw) {
			return true
		}
	}
	return false
}

// dummyMarkers are substrings that indicate a placeholder / documented-example
// credential rather than a real leaked value. Match is case-insensitive.
var dummyMarkers = []string{
	"EXAMPLE",
	"FAKE",
	"DUMMY",
	"PLACEHOLDER",
	"REPLACE_ME",
	"REPLACE-ME",
	"YOUR_KEY",
	"YOUR-KEY",
	"YOUR_SECRET",
	"YOUR-SECRET",
	"CHANGE_ME",
	"CHANGE-ME",
	"NOT_A_REAL",
	"NOT-A-REAL",
	"XXXXXXXXX",  // ≥9 X is a strong signal
	"AAAAAAAAA",  // ≥9 A
	"0000000000", // long run of zeros
	"1234567890", // sequence
	"<your-",
	"<insert-",
	"<replace-",
}

// IsDummySecret returns true when the value looks like a placeholder /
// example credential rather than a real leaked one.
func IsDummySecret(secret string) bool {
	if secret == "" {
		return false
	}
	upper := strings.ToUpper(secret)
	for _, m := range dummyMarkers {
		if strings.Contains(upper, strings.ToUpper(m)) {
			return true
		}
	}
	return false
}
