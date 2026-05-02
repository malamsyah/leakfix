package agent_test

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/malamsyah/leakfix/internal/agent"
)

// scriptedClient returns canned responses in turn order; once exhausted, it
// returns an end_turn so the agent loop terminates cleanly.
type scriptedClient struct {
	turns int
	steps []scriptStep
}

type scriptStep func(req agent.Request) (agent.Response, error)

func (s *scriptedClient) Complete(_ context.Context, req agent.Request) (agent.Response, error) {
	if s.turns >= len(s.steps) {
		return agent.Response{StopReason: "end_turn"}, nil
	}
	resp, err := s.steps[s.turns](req)
	s.turns++
	return resp, err
}

func toolUse(id, name string, input any) agent.ContentBlock {
	b, _ := json.Marshal(input)
	return agent.ContentBlock{Type: "tool_use", ToolUseID: id, Name: name, Input: b}
}

func mkResp(stop string, blocks ...agent.ContentBlock) agent.Response {
	return agent.Response{Content: blocks, StopReason: stop}
}

func newID() string {
	idCounter++
	return "tu_" + strconv.Itoa(idCounter)
}

var idCounter int
