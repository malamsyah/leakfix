package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/malamsyah/leakfix/internal/scanner"
	"github.com/spf13/cobra"
)

func newScanCmd() *cobra.Command {
	var (
		accessMap           bool
		format              string
		outputPath          string
		confidence          string
		strict              bool
		includeTestFiles    bool
		includeDummySecrets bool
		noFilter            bool
	)
	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Run Kingfisher on a local path or remote GitHub repo",
		Long: "Scan a local repository path, or a remote GitHub repo URL " +
			"(github.com/owner/repo, https://github.com/owner/repo, or git@github.com:owner/repo.git). " +
			"Remote scans require GH_TOKEN or `gh auth login`. For org-wide scans, use `leakfix scan-org`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			target := args[0]
			if scanner.IsRemoteTarget(target) {
				fmt.Fprintf(os.Stderr, "scanning remote repository %s — kingfisher will clone\n", target)
			}
			s := scanner.New()
			findings, meta, err := s.Scan(ctx, target, scanner.Options{
				AccessMap:  accessMap,
				Confidence: confidence,
			})
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
				if err := scanner.WriteMarkdown(out, args[0], findings, meta); err != nil {
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
	cmd.Flags().BoolVar(&accessMap, "access-map", false, "run kingfisher with --access-map (slower; needs cloud creds)")
	cmd.Flags().StringVar(&format, "format", "md", "output format: md|json|sarif")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "write to file instead of stdout")
	cmd.Flags().StringVar(&confidence, "confidence", "medium", "kingfisher confidence threshold: low|medium|high")
	cmd.Flags().BoolVar(&strict, "strict", false, "exit non-zero if any finding is present")
	cmd.Flags().BoolVar(&includeTestFiles, "include-test-files", false, "include findings in obvious test paths (testdata/, _test.go, fixtures/, ...)")
	cmd.Flags().BoolVar(&includeDummySecrets, "include-dummy-secrets", false, "include findings whose value contains EXAMPLE/DUMMY/FAKE/PLACEHOLDER markers")
	cmd.Flags().BoolVar(&noFilter, "no-filter", false, "shorthand for --include-test-files --include-dummy-secrets")
	return cmd
}
