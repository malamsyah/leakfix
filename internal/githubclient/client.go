package githubclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"

	gh "github.com/google/go-github/v68/github"
)

// Client wraps go-github with the auth precedence required by SPEC §5.1:
// gh CLI auth first, then GH_TOKEN, then error.
type Client struct {
	gh *gh.Client
}

// New creates a Client by trying `gh auth token` first, then GH_TOKEN.
func New(ctx context.Context) (*Client, error) {
	token := strings.TrimSpace(os.Getenv("GH_TOKEN"))
	if token == "" {
		// Try gh CLI
		if out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output(); err == nil {
			token = strings.TrimSpace(string(out))
		}
	}
	if token == "" {
		return nil, errors.New("no GitHub auth: install `gh` and run `gh auth login`, or set GH_TOKEN")
	}
	return &Client{gh: gh.NewClient(nil).WithAuthToken(token)}, nil
}

// OpenPROptions describes a PR to be opened.
type OpenPROptions struct {
	Title string
	Body  string
	Head  string
	Base  string
}

// OpenPR creates a pull request and returns (number, html_url).
func (c *Client) OpenPR(ctx context.Context, owner, repo string, opts OpenPROptions) (int, string, error) {
	pr, _, err := c.gh.PullRequests.Create(ctx, owner, repo, &gh.NewPullRequest{
		Title: gh.Ptr(opts.Title),
		Body:  gh.Ptr(opts.Body),
		Head:  gh.Ptr(opts.Head),
		Base:  gh.Ptr(opts.Base),
	})
	if err != nil {
		return 0, "", fmt.Errorf("create pr: %w", err)
	}
	return pr.GetNumber(), pr.GetHTMLURL(), nil
}

// OpenIssue creates an issue and returns (number, html_url).
func (c *Client) OpenIssue(ctx context.Context, owner, repo, title, body string) (int, string, error) {
	is, _, err := c.gh.Issues.Create(ctx, owner, repo, &gh.IssueRequest{
		Title: gh.Ptr(title),
		Body:  gh.Ptr(body),
	})
	if err != nil {
		return 0, "", fmt.Errorf("create issue: %w", err)
	}
	return is.GetNumber(), is.GetHTMLURL(), nil
}

// UpdateIssueBody overwrites the body of an existing issue.
func (c *Client) UpdateIssueBody(ctx context.Context, owner, repo string, number int, body string) error {
	_, _, err := c.gh.Issues.Edit(ctx, owner, repo, number, &gh.IssueRequest{
		Body: gh.Ptr(body),
	})
	return err
}

// FindOpenPRForBranch searches for an open PR whose head matches branch.
// Returns (0, "", nil) if none found.
func (c *Client) FindOpenPRForBranch(ctx context.Context, owner, repo, branch string) (int, string, error) {
	prs, resp, err := c.gh.PullRequests.List(ctx, owner, repo, &gh.PullRequestListOptions{
		State: "open",
		Head:  fmt.Sprintf("%s:%s", owner, branch),
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return 0, "", nil
		}
		return 0, "", err
	}
	if len(prs) == 0 {
		return 0, "", nil
	}
	return prs[0].GetNumber(), prs[0].GetHTMLURL(), nil
}

// DefaultBranch returns the repo's default branch (e.g. "main").
func (c *Client) DefaultBranch(ctx context.Context, owner, repo string) (string, error) {
	r, _, err := c.gh.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", err
	}
	return r.GetDefaultBranch(), nil
}
