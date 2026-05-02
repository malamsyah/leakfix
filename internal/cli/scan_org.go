package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanOrgCmd() *cobra.Command {
	var (
		asUser              bool
		limit               int
		includeContributors bool
		listOnly            bool
		accessMap           bool
		confidence          string
		apiURL              string
		excludeRepos        []string
		format              string
		outputPath          string
		strict              bool
		includeTestFiles    bool
		includeDummySecrets bool
		noFilter            bool
	)

	cmd := &cobra.Command{
		Use:   "scan-org <owner> [<owner>...]",
		Short: "Scan every repository in one or more GitHub orgs (or users)",
		Long: "Enumerate and scan every repository owned by the given GitHub " +
			"organization(s) using `kingfisher scan github`. By default the " +
			"argument is treated as an organization; use --user to treat it " +
			"as a personal account. Requires GH_TOKEN or `gh auth login`.\n\n" +
			"Vendored / dummy / test-fixture filters apply identically to " +
			"local scans. The output groups findings per repository and " +
			"includes a clickable GitHub link for every commit.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			gopts := scanner.GitHubScanOptions{
				RepoCloneLimit:      limit,
				IncludeContributors: includeContributors,
				ListOnly:            listOnly,
				AccessMap:           accessMap,
				Confidence:          confidence,
				APIURL:              apiURL,
				ExcludeRepos:        excludeRepos,
			}
			for _, owner := range args {
				owner = strings.TrimSpace(owner)
				if owner == "" {
					continue
				}
				if asUser {
					gopts.Users = append(gopts.Users, owner)
				} else {
					gopts.Organizations = append(gopts.Organizations, owner)
				}
			}

			label := "organization(s)"
			if asUser {
				label = "user(s)"
			}
			fmt.Fprintf(os.Stderr, "scanning GitHub %s: %s — kingfisher will clone matching repos\n", label, strings.Join(args, ", "))

			s := scanner.New()
			findings, meta, err := s.ScanGitHub(ctx, gopts)
			if err != nil {
				return err
			}

			fopts := scanner.FilterOptions{
				IncludeTestFiles:    includeTestFiles || noFilter,
				IncludeDummySecrets: includeDummySecrets || noFilter,
			}
			fres := scanner.ApplyFilters(findings, fopts)
			findings = fres.Kept
			if fres.DroppedVendored > 0 || fres.DroppedTestPath > 0 || fres.DroppedDummyValue > 0 {
				fmt.Fprintf(os.Stderr, "filtered: %d vendored, %d test paths, %d dummy/placeholder values (use --no-filter for test/dummy; vendored is always skipped)\n",
					fres.DroppedVendored, fres.DroppedTestPath, fres.DroppedDummyValue)
			}

			out := io.Writer(os.Stdout)
			if outputPath != "" {
				f, err := os.Create(outputPath)
				if err != nil {
					return err
				}
				defer f.Close()
				out = f
			}

			switch format {
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(map[string]any{
					"kingfisher_version": meta.KingfisherVersion,
					"findings":           findings,
				}); err != nil {
					return err
				}
			case "sarif":
				if err := scanner.WriteSARIF(out, findings); err != nil {
					return err
				}
			case "", "md":
				if err := writeOrgMarkdown(out, args, findings, meta); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported --format %q (want md|json|sarif)", format)
			}

			if strict && len(findings) > 0 {
				return fmt.Errorf("found %d secret(s); --strict was set", len(findings))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&asUser, "user", false, "treat the positional argument(s) as user accounts instead of organizations")
	cmd.Flags().IntVar(&limit, "limit", 0, "max number of repositories to clone (0 = no cap)")
	cmd.Flags().BoolVar(&includeContributors, "include-contributors", false, "also scan repositories owned by org/user contributors")
	cmd.Flags().BoolVar(&listOnly, "list-only", false, "list matching repositories without scanning them")
	cmd.Flags().BoolVar(&accessMap, "access-map", false, "run kingfisher with --access-map (slower; needs cloud creds)")
	cmd.Flags().StringVar(&confidence, "confidence", "medium", "kingfisher confidence threshold: low|medium|high")
	cmd.Flags().StringVar(&apiURL, "api-url", "", "override the GitHub API URL (e.g. for GitHub Enterprise)")
	cmd.Flags().StringSliceVar(&excludeRepos, "exclude-repo", nil, "skip these repos (format: owner/repo, repeatable)")
	cmd.Flags().StringVar(&format, "format", "md", "output format: md|json|sarif")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "write to file instead of stdout")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero if any finding is present")
	cmd.Flags().BoolVar(&includeTestFiles, "include-test-files", false, "include findings in obvious test paths (testdata/, _test.go, fixtures/, ...)")
	cmd.Flags().BoolVar(&includeDummySecrets, "include-dummy-secrets", false, "include findings whose value contains EXAMPLE/DUMMY/FAKE/PLACEHOLDER markers")
	cmd.Flags().BoolVar(&noFilter, "no-filter", false, "shorthand for --include-test-files --include-dummy-secrets")
	return cmd
}

// writeOrgMarkdown groups findings by repository (derived from the GitHub
// blob URL) and emits a per-repo section. Findings without a parseable
// repository fall under an "(unknown repository)" group.
func writeOrgMarkdown(w io.Writer, owners []string, findings []scanner.Finding, meta scanner.Meta) error {
	if _, err := fmt.Fprintf(w, "# GitHub org scan: %s\n\n", strings.Join(owners, ", ")); err != nil {
		return err
	}
	if meta.KingfisherVersion != "" {
		fmt.Fprintf(w, "_kingfisher %s_\n\n", meta.KingfisherVersion)
	}
	fmt.Fprintf(w, "**Total findings:** %d\n\n", len(findings))

	groups := map[string][]scanner.Finding{}
	for _, f := range findings {
		key := repoKeyFromFinding(f)
		groups[key] = append(groups[key], f)
	}
	repos := make([]string, 0, len(groups))
	for k := range groups {
		repos = append(repos, k)
	}
	sort.Strings(repos)

	for _, repo := range repos {
		fmt.Fprintf(w, "## %s — %d finding(s)\n\n", repo, len(groups[repo]))
		for _, f := range groups[repo] {
			fmt.Fprintf(w, "- `%s`", f.RuleID)
			if preview := scanner.RedactedPreview(f.Secret); preview != "" {
				fmt.Fprintf(w, " · `%s`", preview)
			}
			if len(f.Locations) > 0 {
				loc := f.Locations[0]
				fmt.Fprintf(w, " · `%s:%d`", loc.File, loc.Line)
				if loc.BlobURL != "" {
					fmt.Fprintf(w, " — [view on GitHub](%s)", loc.BlobURL)
				}
				if loc.CommitURL != "" {
					short := loc.CommitSHA
					if len(short) > 7 {
						short = short[:7]
					}
					fmt.Fprintf(w, " · [commit %s](%s)", short, loc.CommitURL)
				}
			}
			if f.Validated {
				fmt.Fprintf(w, " · **validated as live**")
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// repoKeyFromFinding derives "owner/repo" from a finding's blob URL.
// GitHub URL shape: https://github.com/<owner>/<repo>/blob/<sha>/<path>#L<line>
func repoKeyFromFinding(f scanner.Finding) string {
	for _, loc := range f.Locations {
		if loc.BlobURL == "" {
			continue
		}
		const prefix = "https://github.com/"
		if !strings.HasPrefix(loc.BlobURL, prefix) {
			continue
		}
		rest := strings.TrimPrefix(loc.BlobURL, prefix)
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
	}
	return "(unknown repository)"
}
