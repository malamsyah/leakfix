package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/malamsyah/leakfix/internal/doctor"
	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verify external prerequisites",
		Long:  "Verify that kingfisher, git-filter-repo, gh CLI, and ANTHROPIC_API_KEY are available.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), doctor.DefaultTimeout)
			defer cancel()
			rep := doctor.Run(ctx)

			switch format {
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			case "", "text", "human":
				rep.WriteHuman(os.Stdout)
			default:
				return fmt.Errorf("unsupported --format %q (want text|json)", format)
			}
			if !rep.OK {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", "text", "output format: text|json")
	return cmd
}
