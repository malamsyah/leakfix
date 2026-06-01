package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/malamsyah/leakfix/internal/plan"
)

// scrubbingClient wraps a Client and refuses to forward any Request whose
// payload still contains a literal secret value. It is the last-line defence
// at the LLM boundary: in normal operation, read_file already redacts file
// content the agent sees, but if a literal slips through any other channel
// (a future tool, a logging mistake, a model hallucination quoting back the
// secret it inferred), this layer fails closed rather than exfiltrating.
type scrubbingClient struct {
	inner   Client
	secrets []string
}

// newScrubbingClient returns inner unchanged when there are no known
// secrets to defend against, avoiding pointless allocations in tests and
// summary-only scan modes.
func newScrubbingClient(inner Client, secrets []string) Client {
	cleaned := dedupNonEmpty(secrets)
	if len(cleaned) == 0 {
		return inner
	}
	return &scrubbingClient{inner: inner, secrets: cleaned}
}

func (s *scrubbingClient) Complete(ctx context.Context, req Request) (Response, error) {
	if leak, ok := findLiteralLeak(req, s.secrets); ok {
		return Response{}, fmt.Errorf("refusing to send request to LLM: literal secret %s would be exfiltrated", plan.Placeholder(leak))
	}
	return s.inner.Complete(ctx, req)
}

// findLiteralLeak walks every user-supplied string in req that will be
// serialised onto the wire and reports the first literal secret found.
// The system prompt is also checked even though we author it ourselves,
// because future edits could accidentally interpolate finding data.
func findLiteralLeak(req Request, secrets []string) (string, bool) {
	if leak, ok := containsAnySecret(req.System, secrets); ok {
		return leak, true
	}
	for _, m := range req.Messages {
		for _, b := range m.Content {
			if leak, ok := blockHasSecret(b, secrets); ok {
				return leak, true
			}
		}
	}
	return "", false
}

func blockHasSecret(b ContentBlock, secrets []string) (string, bool) {
	if leak, ok := containsAnySecret(b.Text, secrets); ok {
		return leak, true
	}
	if leak, ok := containsAnySecret(b.Result, secrets); ok {
		return leak, true
	}
	if leak, ok := containsAnySecret(b.Name, secrets); ok {
		return leak, true
	}
	if len(b.Input) > 0 {
		// Recurse into JSON values so nested string fields are inspected.
		if leak, ok := jsonHasSecret(b.Input, secrets); ok {
			return leak, true
		}
	}
	return "", false
}

func jsonHasSecret(raw json.RawMessage, secrets []string) (string, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Unparseable JSON — fall back to scanning the bytes directly.
		return containsAnySecret(string(raw), secrets)
	}
	return walkAnyForSecret(v, secrets)
}

func walkAnyForSecret(v any, secrets []string) (string, bool) {
	switch t := v.(type) {
	case string:
		return containsAnySecret(t, secrets)
	case map[string]any:
		for _, child := range t {
			if leak, ok := walkAnyForSecret(child, secrets); ok {
				return leak, true
			}
		}
	case []any:
		for _, child := range t {
			if leak, ok := walkAnyForSecret(child, secrets); ok {
				return leak, true
			}
		}
	}
	return "", false
}

func containsAnySecret(s string, secrets []string) (string, bool) {
	if s == "" {
		return "", false
	}
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		if strings.Contains(s, sec) {
			return sec, true
		}
	}
	return "", false
}

func dedupNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
