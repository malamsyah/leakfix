package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Scanner is a thin wrapper around the kingfisher CLI.
type Scanner struct {
	binary string
	// ProgressWriter receives kingfisher's stderr (per-repo cloning /
	// scanning progress). Defaults to os.Stderr when nil. Tests may set
	// it to io.Discard to silence chatter.
	ProgressWriter io.Writer
}

func New() *Scanner { return &Scanner{binary: "kingfisher"} }

// NewWithBinary lets tests substitute a custom path or stub.
func NewWithBinary(path string) *Scanner { return &Scanner{binary: path} }

// progressWriter returns the configured ProgressWriter or os.Stderr.
func (s *Scanner) progressWriter() io.Writer {
	if s.ProgressWriter != nil {
		return s.ProgressWriter
	}
	return os.Stderr
}

// runKingfisher streams stderr to the progress writer in real time while
// capturing stdout for the caller. On non-zero exit, the last ~64KB of
// stderr is surfaced as the error message — kingfisher returns non-zero
// when findings are present (e.g. exit 200), so an empty stdout is the
// only signal that the run actually failed.
func (s *Scanner) runKingfisher(ctx context.Context, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.binary, args...)
	cmd.Env = env
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderrTail tailBuffer
	cmd.Stderr = io.MultiWriter(s.progressWriter(), &stderrTail)
	err := cmd.Run()
	out := stdout.Bytes()
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			if len(bytes.TrimSpace(out)) == 0 {
				return nil, fmt.Errorf("kingfisher: %s", strings.TrimSpace(stderrTail.String()))
			}
		} else {
			return nil, fmt.Errorf("kingfisher: %w", err)
		}
	}
	return out, nil
}

// tailBuffer keeps the last N bytes written to it. Used to surface
// kingfisher's stderr in error messages without unbounded memory growth.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	if t.max == 0 {
		t.max = 64 * 1024
	}
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

// isGitHubURL returns true when s already points at github.com, ignoring
// scheme. False for the malformed local-tmpdir URLs kingfisher 1.x emits
// during remote-clone scans.
func isGitHubURL(s string) bool {
	if s == "" {
		return false
	}
	return strings.HasPrefix(s, "https://github.com/") ||
		strings.HasPrefix(s, "http://github.com/")
}

// normaliseGitHubRepoURL converts whatever shape the repository_url has
// into "https://github.com/<owner>/<repo>" (no .git, no trailing slash).
// Returns "" when the input doesn't look like GitHub.
//
// Kingfisher 1.x's remote-clone path can pass either a real
// "https://github.com/owner/repo" or a tmpdir whose last segment is the
// flattened form "https___github.com_owner_repo". Both are recognised.
func normaliseGitHubRepoURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")
	switch {
	case strings.HasPrefix(s, "https://github.com/"):
		return s
	case strings.HasPrefix(s, "http://github.com/"):
		return "https://github.com/" + strings.TrimPrefix(s, "http://github.com/")
	case strings.HasPrefix(s, "git@github.com:"):
		return "https://github.com/" + strings.TrimPrefix(s, "git@github.com:")
	case strings.HasPrefix(s, "github.com/"):
		return "https://" + s
	}
	// Fall back to kingfisher's flattened-tmpdir form. The path's *last*
	// directory looks like "https___github.com_<owner>_<repo>".
	for _, seg := range strings.Split(s, "/") {
		if rest, ok := strings.CutPrefix(seg, "https___github.com_"); ok {
			parts := strings.SplitN(rest, "_", 2)
			if len(parts) == 2 {
				return "https://github.com/" + parts[0] + "/" + parts[1]
			}
		}
	}
	return ""
}

func buildGitHubBlobURL(repoURL, commit, path string, line int) string {
	if repoURL == "" || commit == "" || path == "" {
		return ""
	}
	url := repoURL + "/blob/" + commit + "/" + strings.TrimPrefix(path, "/")
	if line > 0 {
		url += "#L" + fmt.Sprintf("%d", line)
	}
	return url
}

func buildGitHubCommitURL(repoURL, commit string) string {
	if repoURL == "" || commit == "" {
		return ""
	}
	return repoURL + "/commit/" + commit
}

// IsRemoteTarget reports whether target looks like a remote GitHub URL.
// Anything that starts with "github.com/", "https://github.com/", or
// "git@github.com:" is treated as remote and forwarded to kingfisher
// untouched (kingfisher clones it). Local paths are scanned in place.
func IsRemoteTarget(target string) bool {
	t := strings.TrimSpace(target)
	if t == "" {
		return false
	}
	switch {
	case strings.HasPrefix(t, "github.com/"),
		strings.HasPrefix(t, "https://github.com/"),
		strings.HasPrefix(t, "http://github.com/"),
		strings.HasPrefix(t, "git@github.com:"):
		return true
	}
	return false
}

// Scan runs `kingfisher scan --format json [--access-map]` on repoPath, parses
// the JSON output, and deduplicates findings by secret hash.
func (s *Scanner) Scan(ctx context.Context, repoPath string, opts Options) ([]Finding, Meta, error) {
	args := []string{"scan", "--format", "json"}
	if opts.AccessMap {
		args = append(args, "--access-map")
	}
	if opts.Confidence != "" {
		args = append(args, "--confidence", opts.Confidence)
	}
	// Skip vendored / dependency directories at the kingfisher level so we
	// don't waste time reading files we'd filter out post-hoc anyway.
	for _, seg := range vendoredPathSegments {
		args = append(args, "--exclude", seg)
	}
	args = append(args, repoPath)

	out, err := s.runKingfisher(ctx, args, os.Environ())
	if err != nil {
		return nil, Meta{}, err
	}
	version, _ := s.Version(ctx)
	findings, err := ParseFindings(out)
	if err != nil {
		return nil, Meta{}, err
	}
	return findings, Meta{KingfisherVersion: version, Confidence: opts.Confidence, AccessMap: opts.AccessMap}, nil
}

// ScanGitHub runs `kingfisher scan github [--organization ...] [--user ...]`
// against the GitHub API, cloning each matching repo and scanning it. Either
// Organizations or Users must be set; both can be combined.
//
// Auth: kingfisher reads KF_GITHUB_TOKEN. leakfix derives this from
// GH_TOKEN, GITHUB_TOKEN, or `gh auth token` — see withGitHubAuth.
//
// When opts.ListOnly is true, kingfisher emits a plain-text URL list
// instead of JSON; ScanGitHub returns synthetic Finding stubs (one per
// repo) so callers can render or count them. No actual scanning happens.
func (s *Scanner) ScanGitHub(ctx context.Context, opts GitHubScanOptions) ([]Finding, Meta, error) {
	if len(opts.Organizations) == 0 && len(opts.Users) == 0 {
		return nil, Meta{}, fmt.Errorf("ScanGitHub: at least one --organization or --user is required")
	}
	args := []string{"scan", "github"}
	if !opts.ListOnly {
		args = append(args, "--format", "json")
	}
	for _, o := range opts.Organizations {
		args = append(args, "--organization", o)
	}
	for _, u := range opts.Users {
		args = append(args, "--user", u)
	}
	if opts.RepoCloneLimit > 0 {
		args = append(args, "--repo-clone-limit", fmt.Sprintf("%d", opts.RepoCloneLimit))
	}
	if opts.IncludeContributors {
		args = append(args, "--include-contributors")
	}
	if opts.ListOnly {
		args = append(args, "--list-only")
	}
	if opts.AccessMap {
		args = append(args, "--access-map")
	}
	if opts.Confidence != "" {
		args = append(args, "--confidence", opts.Confidence)
	}
	if opts.APIURL != "" {
		args = append(args, "--api-url", opts.APIURL)
	}
	for _, e := range opts.ExcludeRepos {
		args = append(args, "--github-exclude", e)
	}
	for _, seg := range vendoredPathSegments {
		args = append(args, "--exclude", seg)
	}

	out, err := s.runKingfisher(ctx, args, withGitHubAuth(ctx, os.Environ()))
	if err != nil {
		return nil, Meta{}, err
	}
	version, _ := s.Version(ctx)
	if opts.ListOnly {
		findings := parseListOnlyOutput(out)
		return findings, Meta{KingfisherVersion: version, Confidence: opts.Confidence, AccessMap: opts.AccessMap}, nil
	}
	findings, err := ParseFindings(out)
	if err != nil {
		return nil, Meta{}, err
	}
	return findings, Meta{KingfisherVersion: version, Confidence: opts.Confidence, AccessMap: opts.AccessMap}, nil
}

// parseListOnlyOutput converts kingfisher's `--list-only` text output (one
// repo URL per line) into synthetic Findings so the rest of the leakfix
// pipeline can render them.
func parseListOnlyOutput(out []byte) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "http") {
			continue
		}
		repo := normaliseGitHubRepoURL(line)
		if repo == "" {
			continue
		}
		findings = append(findings, Finding{
			ID:     repo,
			RuleID: "kingfisher.list_only",
			Locations: []Location{{
				File:    "(repository discovered; use without --list-only to scan)",
				Line:    0,
				BlobURL: repo,
			}},
		})
	}
	return findings
}

// withGitHubAuth derives KF_GITHUB_TOKEN for the kingfisher subprocess from
// (in order) an existing KF_GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKEN, or
// `gh auth token`. Returns env unchanged if no token can be discovered —
// the kingfisher subprocess will fail with a clear 401 in that case.
func withGitHubAuth(ctx context.Context, env []string) []string {
	for _, e := range env {
		if strings.HasPrefix(e, "KF_GITHUB_TOKEN=") && len(e) > len("KF_GITHUB_TOKEN=") {
			return env
		}
	}
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		if out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output(); err == nil {
			token = strings.TrimSpace(string(out))
		}
	}
	if token == "" {
		return env
	}
	return append(env, "KF_GITHUB_TOKEN="+token)
}

// Version invokes `kingfisher --version` and returns the trimmed string.
func (s *Scanner) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, s.binary, "--version").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// kingfisherJSON describes the subset of fields we consume. Non-strict: extra
// fields are ignored, so minor schema drift across kingfisher versions is OK.
//
// Kingfisher 0.x emitted `{"findings": [<finding objects>]}` with each
// finding containing flat `secret`, `path`, `line` fields.
//
// Kingfisher 1.x emits TWO concatenated JSON documents:
//
//  1. detail doc: `{"findings": [<v1 finding>], "metadata": {...}}` with
//     each finding shaped as {rule: {id, name}, finding: {snippet, path,
//     line, validation: {status}, fingerprint, git_metadata: {commit: ...},
//     ...}}.
//  2. summary doc: `{"findings": <count>, "findings_by_rule": [...], ...}`.
//
// When findings: 0 in the summary, kingfisher 1.x omits the detail doc and
// emits only the summary. In that case we degrade to summary-synthesis so
// that `leakfix scan` still reports a count.
type kingfisherJSON struct {
	Findings       json.RawMessage `json:"findings"`
	FindingsByRule [][]any         `json:"findings_by_rule"`
}

// rawFinding accepts BOTH legacy 0.x flat shape and 1.x nested shape. After
// JSON unmarshalling we call normalize() to flatten 1.x into the same fields
// the rest of the parser expects.
type rawFinding struct {
	// 0.x flat fields (kept for backward compatibility)
	ID         string        `json:"id"`
	RuleID     string        `json:"rule_id"`
	Rule       string        `json:"rule_str"` // hint when Rule is a string
	Provider   string        `json:"provider"`
	Secret     string        `json:"secret"`
	SecretHash string        `json:"secret_hash"`
	Validated  bool          `json:"validated"`
	Path       string        `json:"path"`
	File       string        `json:"file"`
	Line       int           `json:"line"`
	Commit     string        `json:"commit"`
	BlobURL    string        `json:"blob_url"`
	CommitURL  string        `json:"commit_url"`
	Locations  []rawLocation `json:"locations"`
	AccessMap  *rawAccessMap `json:"access_map"`

	// 1.x nested fields. `rule` is `{id, name}` in 1.x but a bare string
	// in 0.x — handled by RawMessage + lazy decode in normalize().
	V1Rule    json.RawMessage `json:"rule"`
	V1Finding *v1Finding      `json:"finding"`
}

type v1Finding struct {
	Snippet     string         `json:"snippet"`
	Fingerprint string         `json:"fingerprint"`
	Confidence  string         `json:"confidence"`
	Validation  *v1Validation  `json:"validation"`
	Path        string         `json:"path"`
	Line        int            `json:"line"`
	GitMetadata *v1GitMetadata `json:"git_metadata"`
	AccessMap   *rawAccessMap  `json:"access_map"`
}

type v1Validation struct {
	Status   string `json:"status"`
	Response string `json:"response"`
}

type v1GitMetadata struct {
	RepositoryURL string            `json:"repository_url"`
	Commit        *v1CommitMetadata `json:"commit"`
	File          *v1FileMetadata   `json:"file"`
}

type v1CommitMetadata struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type v1FileMetadata struct {
	Path string `json:"path"`
	URL  string `json:"url"`
}

type rawLocation struct {
	Path      string `json:"path"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	CommitSHA string `json:"commit"`
	BlobURL   string `json:"blob_url"`
	CommitURL string `json:"commit_url"`
}

type rawAccessMap struct {
	Identity    string   `json:"identity"`
	Permissions []string `json:"permissions"`
	Resources   []string `json:"resources"`
}

// normalize flattens kingfisher 1.x nested fields into the 0.x flat shape
// the rest of the parser uses. Idempotent for 0.x findings.
func (r *rawFinding) normalize() {
	if r.V1Finding == nil && len(r.V1Rule) == 0 {
		return // already 0.x flat
	}
	if r.V1Rule != nil {
		// rule is `{id, name}` — extract id.
		var rule struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(r.V1Rule, &rule); err == nil {
			if r.RuleID == "" {
				r.RuleID = rule.ID
			}
			if r.Rule == "" {
				r.Rule = rule.Name
			}
		}
	}
	if r.V1Finding != nil {
		f := r.V1Finding
		if r.Secret == "" {
			r.Secret = f.Snippet
		}
		if r.SecretHash == "" {
			r.SecretHash = f.Fingerprint
		}
		if r.Path == "" {
			r.Path = f.Path
		}
		if r.Line == 0 {
			r.Line = f.Line
		}
		if f.GitMetadata != nil {
			if r.Commit == "" && f.GitMetadata.Commit != nil {
				r.Commit = f.GitMetadata.Commit.ID
			}
			if r.CommitURL == "" && f.GitMetadata.Commit != nil {
				r.CommitURL = f.GitMetadata.Commit.URL
			}
			if r.BlobURL == "" && f.GitMetadata.File != nil {
				r.BlobURL = f.GitMetadata.File.URL
			}
			// Kingfisher 1.x's remote-clone path emits malformed URLs that
			// embed the local tmpdir (e.g. /var/folders/.../tmpXYZ/...). When
			// the URL doesn't point at a real github.com host, rebuild it
			// from the components we trust: repository_url + commit id + path.
			repo := normaliseGitHubRepoURL(f.GitMetadata.RepositoryURL)
			// Fall back to extracting the repo from the (malformed) URLs
			// kingfisher emitted; they embed the flattened repo segment
			// even when repository_url is unhelpful.
			if repo == "" {
				repo = normaliseGitHubRepoURL(r.BlobURL)
			}
			if repo == "" {
				repo = normaliseGitHubRepoURL(r.CommitURL)
			}
			if repo != "" {
				if !isGitHubURL(r.BlobURL) {
					r.BlobURL = buildGitHubBlobURL(repo, r.Commit, f.Path, f.Line)
				}
				if !isGitHubURL(r.CommitURL) {
					r.CommitURL = buildGitHubCommitURL(repo, r.Commit)
				}
			}
		}
		if !r.Validated && f.Validation != nil && strings.EqualFold(f.Validation.Status, "Active") {
			r.Validated = true
		}
		if r.AccessMap == nil && f.AccessMap != nil {
			r.AccessMap = f.AccessMap
		}
	}
}

// ParseFindings reads kingfisher JSON output and returns deduplicated findings.
// Tolerates three shapes:
//   - bare array (legacy)
//   - kingfisher 0.x: single object with `findings` as an array
//   - kingfisher 1.x: TWO concatenated objects — first has detail, second has summary
func ParseFindings(data []byte) ([]Finding, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, nil
	}

	var raws []rawFinding
	if data[0] == '[' {
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, fmt.Errorf("parse kingfisher json (array): %w", err)
		}
	} else {
		// Stream-decode every concatenated JSON object in data. Kingfisher 1.x
		// emits a detail doc followed by a summary doc; 0.x emits a single doc.
		dec := json.NewDecoder(bytes.NewReader(data))
		var summaryByRule [][]any
		var summaryDisplayCount int
		var detailFound bool
		for {
			var doc kingfisherJSON
			if err := dec.Decode(&doc); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("parse kingfisher json: %w", err)
			}
			if len(doc.Findings) > 0 && doc.Findings[0] == '[' {
				var docRaws []rawFinding
				if err := json.Unmarshal(doc.Findings, &docRaws); err != nil {
					return nil, fmt.Errorf("parse kingfisher json (findings array): %w", err)
				}
				raws = append(raws, docRaws...)
				detailFound = true
			} else if len(doc.Findings) > 0 {
				_ = json.Unmarshal(doc.Findings, &summaryDisplayCount)
			}
			if len(doc.FindingsByRule) > 0 {
				summaryByRule = doc.FindingsByRule
			}
		}
		// Fallback: only summary data available (no detail array). Synthesize
		// per-rule placeholder findings so `leakfix scan` still reports a count.
		if !detailFound && summaryDisplayCount > 0 && len(summaryByRule) > 0 {
			raws = synthesizeFromSummary(summaryByRule, summaryDisplayCount)
		}
	}

	// Flatten 1.x nested shape into the same fields as 0.x.
	for i := range raws {
		raws[i].normalize()
	}

	dedup := map[string]*Finding{}
	order := []string{}

	for _, r := range raws {
		hash := r.SecretHash
		if hash == "" && r.Secret != "" {
			sum := sha256.Sum256([]byte(r.Secret))
			hash = hex.EncodeToString(sum[:])[:16]
		}
		if hash == "" {
			// Last resort: use rule+path+line as id.
			hash = fmt.Sprintf("%s:%s:%d", chooseStr(r.RuleID, r.Rule), chooseStr(r.Path, r.File), r.Line)
		}

		ruleID := chooseStr(r.RuleID, r.Rule)
		f, ok := dedup[hash]
		if !ok {
			f = &Finding{
				ID:         chooseStr(r.ID, hash),
				RuleID:     ruleID,
				Provider:   r.Provider,
				Secret:     r.Secret,
				SecretHash: hash,
				Validated:  r.Validated,
			}
			if r.AccessMap != nil {
				f.AccessMap = &AccessMap{
					Identity:    r.AccessMap.Identity,
					Permissions: r.AccessMap.Permissions,
					Resources:   r.AccessMap.Resources,
				}
			}
			dedup[hash] = f
			order = append(order, hash)
		} else {
			if !f.Validated && r.Validated {
				f.Validated = true
			}
			if f.AccessMap == nil && r.AccessMap != nil {
				f.AccessMap = &AccessMap{
					Identity:    r.AccessMap.Identity,
					Permissions: r.AccessMap.Permissions,
					Resources:   r.AccessMap.Resources,
				}
			}
		}

		// Attach locations: prefer .locations[]; fall back to top-level path/line.
		if len(r.Locations) > 0 {
			for _, loc := range r.Locations {
				addLocation(f, Location{
					File:      chooseStr(loc.Path, loc.File),
					Line:      loc.Line,
					CommitSHA: loc.CommitSHA,
					BlobURL:   loc.BlobURL,
					CommitURL: loc.CommitURL,
				})
			}
		} else {
			addLocation(f, Location{
				File:      chooseStr(r.Path, r.File),
				Line:      r.Line,
				CommitSHA: r.Commit,
				BlobURL:   r.BlobURL,
				CommitURL: r.CommitURL,
			})
		}
	}

	out := make([]Finding, 0, len(order))
	for _, h := range order {
		f := dedup[h]
		if len(f.Locations) == 0 {
			continue
		}
		out = append(out, *f)
	}
	return out, nil
}

func addLocation(f *Finding, loc Location) {
	if loc.File == "" {
		return
	}
	for _, existing := range f.Locations {
		if existing.File == loc.File && existing.Line == loc.Line && existing.CommitSHA == loc.CommitSHA {
			return
		}
	}
	f.Locations = append(f.Locations, loc)
}

func chooseStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// synthesizeFromSummary builds best-effort raw findings from kingfisher 1.x's
// summary-only output, capped at totalDisplayable so we don't synthesize
// findings the scanner has filtered as sub-threshold. Each entry has no
// file/line/secret detail — enough for `leakfix scan` to display a count
// and for self-scan to detect any non-zero finding count.
func synthesizeFromSummary(byRule [][]any, totalDisplayable int) []rawFinding {
	var out []rawFinding
	for _, entry := range byRule {
		if len(entry) < 2 {
			continue
		}
		name, _ := entry[0].(string)
		count := 1
		switch n := entry[1].(type) {
		case float64:
			count = int(n)
		case int:
			count = n
		}
		ruleID := "kingfisher.summary." + slugify(name)
		for i := 0; i < count; i++ {
			if totalDisplayable > 0 && len(out) >= totalDisplayable {
				return out
			}
			id := fmt.Sprintf("%s#%d", ruleID, i+1)
			out = append(out, rawFinding{
				ID:         id,
				RuleID:     ruleID,
				Rule:       name,
				SecretHash: id, // unique per synthetic finding so they don't dedupe
				Path:       "(detail unavailable in this kingfisher version)",
				Line:       0,
			})
		}
	}
	return out
}

func slugify(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
