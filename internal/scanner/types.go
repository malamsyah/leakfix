package scanner

// Finding is the deduplicated, leakfix-internal representation of a
// Kingfisher detection. Multiple raw Kingfisher findings with the same
// secret value collapse into a single Finding with multiple Locations.
type Finding struct {
	ID         string     `json:"id"`
	RuleID     string     `json:"rule_id"`
	Provider   string     `json:"provider,omitempty"`
	Secret     string     `json:"-"` // never serialised
	SecretHash string     `json:"secret_hash"`
	Validated  bool       `json:"validated"`
	Locations  []Location `json:"locations"`
	AccessMap  *AccessMap `json:"access_map,omitempty"`
}

type Location struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	CommitSHA string `json:"commit_sha,omitempty"`
	// BlobURL is a clickable link to the file at the given line/commit on
	// the upstream host (currently GitHub). Provided by Kingfisher 1.x via
	// git_metadata.file.url; empty when scanning a non-GitHub repo or when
	// kingfisher omits git metadata.
	BlobURL string `json:"blob_url,omitempty"`
	// CommitURL is a clickable link to the commit on the upstream host.
	// Provided by Kingfisher 1.x via git_metadata.commit.url.
	CommitURL string `json:"commit_url,omitempty"`
}

type AccessMap struct {
	Identity    string   `json:"identity,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Resources   []string `json:"resources,omitempty"`
}

// Meta carries scan-level metadata.
type Meta struct {
	KingfisherVersion string `json:"kingfisher_version"`
	Confidence        string `json:"confidence"`
	AccessMap         bool   `json:"access_map"`
}

// Options controls the kingfisher subprocess invocation.
type Options struct {
	AccessMap  bool
	Confidence string
}

// GitHubScanOptions controls org-wide / user-wide scans via
// `kingfisher scan github`. Either Organization OR User must be set.
type GitHubScanOptions struct {
	// Organization names whose repos to scan. Comma-joined when forwarded.
	Organizations []string
	// Users whose repos to scan.
	Users []string
	// RepoCloneLimit caps the number of repos cloned. 0 = no cap.
	RepoCloneLimit int
	// IncludeContributors mirrors kingfisher's --include-contributors.
	IncludeContributors bool
	// ListOnly mirrors kingfisher's --list-only.
	ListOnly bool
	// AccessMap mirrors kingfisher's --access-map.
	AccessMap bool
	// Confidence threshold (low|medium|high).
	Confidence string
	// APIURL overrides the GitHub API endpoint (Enterprise).
	APIURL string
	// ExcludeRepos lists repos to skip in the form "owner/repo".
	ExcludeRepos []string
}

// SecretValues returns the raw secret values for redaction. Only used
// internally; never written to the rendered plan.
func SecretValues(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		if f.Secret != "" {
			out = append(out, f.Secret)
		}
	}
	return out
}
