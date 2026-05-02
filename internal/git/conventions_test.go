package git_test

import (
	"strings"
	"testing"

	"github.com/malamsyah/leakfix/internal/git"
	"github.com/malamsyah/leakfix/internal/plan"
	"github.com/stretchr/testify/assert"
)

func TestBranchName_DeterministicForSameFindings(t *testing.T) {
	p1 := &plan.Plan{Items: []plan.PlanItem{{FindingID: "a"}, {FindingID: "b"}}}
	p2 := &plan.Plan{Items: []plan.PlanItem{{FindingID: "b"}, {FindingID: "a"}}} // order shuffled
	assert.Equal(t, git.BranchName(p1), git.BranchName(p2), "branch name must not depend on order")
}

func TestBranchName_FormatPrefix(t *testing.T) {
	p := &plan.Plan{Items: []plan.PlanItem{{FindingID: "abc"}}}
	bn := git.BranchName(p)
	assert.True(t, strings.HasPrefix(bn, "leakfix/remediate-"), bn)
	assert.Len(t, bn, len("leakfix/remediate-")+8)
}

func TestBuildCommitMessage_NoSecrets(t *testing.T) {
	p := &plan.Plan{
		Items: []plan.PlanItem{{
			FindingID:   "f1",
			DisplayName: "AWS IAM",
			Locations:   []plan.Location{{File: "x.go", Line: 1}},
		}},
	}
	msg := git.BuildCommitMessage(p, 42)
	assert.Contains(t, msg, "fix(security):")
	assert.Contains(t, msg, "AWS IAM in x.go")
	assert.Contains(t, msg, "Tracking issue: #42")
	assert.Contains(t, msg, "Plan: ")
}
