package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
)

// RefuseDirty errors if the working tree has uncommitted changes (SPEC §13.4).
func RefuseDirty(repoPath string) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("open repo: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("worktree: %w", err)
	}
	status, err := wt.Status()
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if !status.IsClean() {
		return errors.New("working tree is dirty; commit or stash changes before running --apply")
	}
	return nil
}

// CheckoutNewBranch creates and checks out branchName off baseBranch.
// If baseBranch is empty, it uses the current HEAD.
func CheckoutNewBranch(repoPath, branchName, baseBranch string) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}

	var hash plumbing.Hash
	if baseBranch != "" {
		ref, err := repo.Reference(plumbing.NewBranchReferenceName(baseBranch), true)
		if err != nil {
			return fmt.Errorf("base branch %q: %w", baseBranch, err)
		}
		hash = ref.Hash()
	} else {
		head, err := repo.Head()
		if err != nil {
			return err
		}
		hash = head.Hash()
	}

	branchRef := plumbing.NewBranchReferenceName(branchName)
	if err := repo.Storer.SetReference(plumbing.NewHashReference(branchRef, hash)); err != nil {
		return err
	}
	return wt.Checkout(&git.CheckoutOptions{Branch: branchRef})
}

// BranchExists returns true if the given branch exists locally OR on origin.
func BranchExists(ctx context.Context, repoPath, branchName string) (bool, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return false, err
	}
	if _, err := repo.Reference(plumbing.NewBranchReferenceName(branchName), true); err == nil {
		return true, nil
	}
	// Check remote
	if _, err := repo.Reference(plumbing.NewRemoteReferenceName("origin", branchName), true); err == nil {
		return true, nil
	}
	// Fall back to ls-remote (cheap network call) only if origin exists
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "ls-remote", "--heads", "origin", branchName)
	out, err := cmd.Output()
	if err != nil {
		return false, nil
	}
	return strings.TrimSpace(string(out)) != "", nil
}

// CommitAll stages all changes and creates a single commit using msg.
func CommitAll(repoPath, msg string) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return err
	}
	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	if err := wt.AddGlob("."); err != nil {
		return err
	}
	cfg, err := repo.Config()
	if err != nil {
		return err
	}
	name, email := commitIdentity(cfg)
	_, err = wt.Commit(msg, &git.CommitOptions{
		AllowEmptyCommits: false,
		Author:            authorSig(name, email),
	})
	return err
}

func commitIdentity(cfg *config.Config) (string, string) {
	name := cfg.User.Name
	email := cfg.User.Email
	if name == "" {
		name = "leakfix"
	}
	if email == "" {
		email = "leakfix@users.noreply.github.com"
	}
	return name, email
}

func authorSig(name, email string) *gitObjectSig {
	return newAuthor(name, email)
}

// PushBranch pushes branchName to origin. Honours GH_TOKEN if present.
func PushBranch(ctx context.Context, repoPath, branchName string) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "push", "-u", "origin", branchName)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git push: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// RemoteOwnerRepo parses origin's URL and returns (owner, repo).
func RemoteOwnerRepo(repoPath string) (string, string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", "", err
	}
	rem, err := repo.Remote("origin")
	if err != nil {
		return "", "", fmt.Errorf("origin remote: %w", err)
	}
	for _, u := range rem.Config().URLs {
		if owner, name, ok := parseGitHubURL(u); ok {
			return owner, name, nil
		}
	}
	return "", "", fmt.Errorf("origin URL is not a github.com remote")
}

func parseGitHubURL(u string) (owner, name string, ok bool) {
	u = strings.TrimSuffix(u, ".git")
	switch {
	case strings.HasPrefix(u, "git@github.com:"):
		rest := strings.TrimPrefix(u, "git@github.com:")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	case strings.HasPrefix(u, "https://github.com/"):
		rest := strings.TrimPrefix(u, "https://github.com/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}
	return "", "", false
}

// ResolvePath joins repoPath and rel safely. Returns an absolute path or error.
func ResolvePath(repoPath, rel string) (string, error) {
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute paths not allowed: %q", rel)
	}
	return filepath.Join(repoPath, rel), nil
}
