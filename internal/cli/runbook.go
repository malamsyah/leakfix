package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/malamsyah/leakfix/internal/runbooks"
	"github.com/spf13/cobra"
)

func newRunbookCmd() *cobra.Command {
	var (
		list   bool
		format string
	)
	cmd := &cobra.Command{
		Use:   "runbook [provider-id]",
		Short: "Print or list bundled runbooks",
		RunE: func(_ *cobra.Command, args []string) error {
			reg, err := runbooks.Load()
			if err != nil {
				return err
			}
			if list {
				return printRunbookList(reg, format)
			}
			if len(args) != 1 {
				return fmt.Errorf("provide a runbook id, or use --list")
			}
			rb, ok := reg.ByID(args[0])
			if !ok {
				return fmt.Errorf("runbook %q not found", args[0])
			}
			fmt.Print(string(rb.Raw))
			return nil
		},
	}
	cmd.Flags().BoolVar(&list, "list", false, "list bundled runbooks")
	cmd.Flags().StringVar(&format, "format", "table", "output format for --list: table|json")
	return cmd
}

func printRunbookList(reg *runbooks.Registry, format string) error {
	all := reg.All()
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })

	switch format {
	case "json":
		type entry struct {
			ID          string   `json:"id"`
			DisplayName string   `json:"display_name"`
			Rules       []string `json:"kingfisher_rules"`
		}
		out := make([]entry, len(all))
		for i, rb := range all {
			out[i] = entry{ID: rb.ID, DisplayName: rb.DisplayName, Rules: rb.KingfisherRules}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "", "table":
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tDISPLAY NAME\tRULES")
		for _, rb := range all {
			rules := strings.Join(rb.KingfisherRules, ", ")
			if rules == "" {
				rules = "(fallback)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", rb.ID, rb.DisplayName, rules)
		}
		return w.Flush()
	default:
		return fmt.Errorf("unsupported --format %q (want table|json)", format)
	}
}
