package agent

import (
	"context"
	"encoding/json"
)

// Client is the abstraction over the Anthropic API. The mock implementation
// in tests returns canned tool-use sequences; the live implementation talks
// to the real API.
type Client interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// Request is the per-call payload sent to the LLM.
type Request struct {
	Model       string
	System      string
	Messages    []Message
	Tools       []ToolDef
	MaxTokens   int
	Temperature float64
}

// Message is one entry in the conversation history.
type Message struct {
	Role    string         // "user" | "assistant"
	Content []ContentBlock // either text or tool_use / tool_result blocks
}

// ContentBlock is a polymorphic chunk of message content.
type ContentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Result    string          `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

// Response is the LLM's reply.
type Response struct {
	Content      []ContentBlock
	StopReason   string // "end_turn" | "tool_use" | "max_tokens" | ...
	InputTokens  int
	OutputTokens int
}

// ToolDef is the tool schema sent to the LLM.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}
