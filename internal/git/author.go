package git

import (
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// gitObjectSig is an alias to keep operations.go reading naturally.
type gitObjectSig = object.Signature

func newAuthor(name, email string) *gitObjectSig {
	return &object.Signature{Name: name, Email: email, When: time.Now()}
}
