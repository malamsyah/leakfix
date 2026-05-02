package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/malamsyah/leakfix/internal/plan"
)

// EditFailure describes a single CodeEdit that could not be applied.
type EditFailure struct {
	File   string
	Reason string
}

// ApplyPlanEdits applies every CodeEdit in p to the working tree. Failures
// are collected per edit; the run continues after each failure (SPEC §12.4).
func ApplyPlanEdits(repoPath string, p *plan.Plan) ([]EditFailure, error) {
	var failures []EditFailure
	for _, item := range p.Items {
		for _, edit := range item.CodeEdits {
			if err := applyOneEdit(repoPath, edit); err != nil {
				failures = append(failures, EditFailure{File: edit.File, Reason: err.Error()})
			}
		}
	}
	return failures, nil
}

func applyOneEdit(repoPath string, edit plan.CodeEdit) error {
	if filepath.IsAbs(edit.File) {
		return fmt.Errorf("absolute path not allowed: %q", edit.File)
	}
	full := filepath.Join(repoPath, edit.File)
	data, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	occurrences := strings.Count(string(data), edit.OldContent)
	switch occurrences {
	case 0:
		return fmt.Errorf("old_content not present in %s (file may have changed)", edit.File)
	case 1:
		// fall through
	default:
		return fmt.Errorf("old_content matches %d times in %s; ambiguous", occurrences, edit.File)
	}
	updated := strings.Replace(string(data), edit.OldContent, edit.NewContent, 1)
	info, err := os.Stat(full)
	mode := os.FileMode(0o600)
	if err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.WriteFile(full, []byte(updated), mode); err != nil {
		return err
	}
	return nil
}
