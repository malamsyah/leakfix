package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// DefaultClient returns a live Anthropic client configured from
// ANTHROPIC_API_KEY. Returns an error if the key is missing.
func DefaultClient() (Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, errors.New("ANTHROPIC_API_KEY is not set")
	}
	c := anthropic.NewClient(option.WithAPIKey(key))
	return &liveClient{c: &c}, nil
}

type liveClient struct {
	c *anthropic.Client
}

// Complete is a thin adapter from our internal types to the SDK's typed
// request. Tool definitions and content blocks are mapped 1:1.
func (l *liveClient) Complete(ctx context.Context, req Request) (Response, error) {
	model := req.Model
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	maxTokens := int64(req.MaxTokens)
	if maxTokens == 0 {
		maxTokens = 4000
	}

	tools := make([]anthropic.ToolUnionParam, 0, len(req.Tools))
	for _, t := range req.Tools {
		var schemaMap map[string]any
		_ = json.Unmarshal(t.InputSchema, &schemaMap)
		props, _ := schemaMap["properties"].(map[string]any)
		schema := anthropic.ToolInputSchemaParam{Properties: props}
		if requiredAny, ok := schemaMap["required"].([]any); ok && len(requiredAny) > 0 {
			required := make([]any, 0, len(requiredAny))
			for _, r := range requiredAny {
				if s, ok := r.(string); ok {
					required = append(required, s)
				}
			}
			if len(required) > 0 {
				if schema.ExtraFields == nil {
					schema.ExtraFields = map[string]any{}
				}
				schema.ExtraFields["required"] = required
			}
		}
		tools = append(tools, anthropic.ToolUnionParam{
			OfTool: &anthropic.ToolParam{
				Name:        t.Name,
				Description: anthropic.String(t.Description),
				InputSchema: schema,
			},
		})
	}

	messages := make([]anthropic.MessageParam, 0, len(req.Messages))
	for _, m := range req.Messages {
		blocks := make([]anthropic.ContentBlockParamUnion, 0, len(m.Content))
		for _, b := range m.Content {
			switch b.Type {
			case "text":
				blocks = append(blocks, anthropic.NewTextBlock(b.Text))
			case "tool_use":
				var inputAny any
				if len(b.Input) > 0 {
					_ = json.Unmarshal(b.Input, &inputAny)
				}
				blocks = append(blocks, anthropic.ContentBlockParamUnion{
					OfRequestToolUseBlock: &anthropic.ToolUseBlockParam{
						ID:    b.ToolUseID,
						Name:  b.Name,
						Input: inputAny,
					},
				})
			case "tool_result":
				toolResult := anthropic.NewToolResultBlock(b.ToolUseID, b.Result, b.IsError)
				blocks = append(blocks, toolResult)
			default:
				blocks = append(blocks, anthropic.NewTextBlock(b.Text))
			}
		}
		role := anthropic.MessageParamRoleUser
		if m.Role == "assistant" {
			role = anthropic.MessageParamRoleAssistant
		}
		messages = append(messages, anthropic.MessageParam{Role: role, Content: blocks})
	}

	system := []anthropic.TextBlockParam{}
	if req.System != "" {
		system = append(system, anthropic.TextBlockParam{Text: req.System})
	}

	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: maxTokens,
		Messages:  messages,
		System:    system,
		Tools:     tools,
	}

	var (
		resp *anthropic.Message
		err  error
	)
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = l.c.Messages.New(ctx, params)
		if err == nil {
			break
		}
		if !shouldRetry(err) {
			break
		}
		select {
		case <-ctx.Done():
			return Response{}, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 500 * time.Millisecond):
		}
	}
	if err != nil {
		return Response{}, fmt.Errorf("anthropic api: %w", err)
	}

	out := Response{StopReason: string(resp.StopReason)}
	out.InputTokens = int(resp.Usage.InputTokens)
	out.OutputTokens = int(resp.Usage.OutputTokens)
	for _, blk := range resp.Content {
		switch v := blk.AsAny().(type) {
		case anthropic.TextBlock:
			out.Content = append(out.Content, ContentBlock{Type: "text", Text: v.Text})
		case anthropic.ToolUseBlock:
			input, _ := json.Marshal(v.Input)
			out.Content = append(out.Content, ContentBlock{
				Type:      "tool_use",
				ToolUseID: v.ID,
				Name:      v.Name,
				Input:     input,
			})
		}
	}
	return out, nil
}

func shouldRetry(err error) bool {
	if err == nil {
		return false
	}
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		s := apiErr.StatusCode
		return s == 429 || s >= 500
	}
	return false
}
