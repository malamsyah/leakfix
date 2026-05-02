package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/malamsyah/leakfix/internal/git"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// initRepo creates an empty git repo with a single committed file so go-git
// has a HEAD to anchor against.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "--initial-branch=main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		require.NoError(t, cmd.Run(), "git "+args[0])
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi\n"), 0o644))
	for _, args := range [][]string{
		{"add", "."},
		{"commit", "-m", "initial"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		require.NoError(t, cmd.Run(), "git "+args[0])
	}
	return dir
}

func TestRefuseDirty_CleanRepoOK(t *testing.T) {
	dir := initRepo(t)
	assert.NoError(t, git.RefuseDirty(dir))
}

func TestRefuseDirty_DirtyRepoErrors(t *testing.T) {
	dir := initRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "new.txt"), []byte("uncommitted"), 0o644))
	err := git.RefuseDirty(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dirty")
}
