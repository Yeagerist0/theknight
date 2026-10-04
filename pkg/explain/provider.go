package explain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider turns a system and a user message into text. LLM is the real
// implementation; tests use a fake.
type Provider interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

// LLM speaks the OpenAI-compatible chat-completions protocol, so it works with
// Gemini, vLLM, Ollama and others. Credentials come from the environment, never
// from flags (a flag value leaks into shell history and process listings).
type LLM struct {
	BaseURL         string // e.g. https://generativelanguage.googleapis.com/v1beta/openai
	APIKey          string
	Model           string
	ReasoningEffort string // "none" turns thinking off on models that think; "" omits the field
	Retries         int    // retries on 429/5xx (default 2)
	HTTP            *http.Client

	// Bookkeeping for evals; not safe for concurrent use.
	Calls    int
	Failures int
}

type chatRequest struct {
	Model           string        `json:"model"`
	Temperature     float64       `json:"temperature"`
	ReasoningEffort string        `json:"reasoning_effort,omitempty"`
	Messages        []chatMessage `json:"messages"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete implements Provider.
func (l *LLM) Complete(ctx context.Context, system, user string) (string, error) {
	l.Calls++
	out, err := l.complete(ctx, system, user)
	if err != nil {
		l.Failures++
	}
	return out, err
}

func (l *LLM) complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:           l.Model,
		Temperature:     0,
		ReasoningEffort: l.ReasoningEffort,
		Messages:        []chatMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
	})
	if err != nil {
		return "", err
	}
	client := l.HTTP
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	retries := l.Retries
	if retries <= 0 {
		retries = 2
	}
	url := strings.TrimRight(l.BaseURL, "/") + "/chat/completions"
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		if l.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+l.APIKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("llm request: %w", err)
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("llm http %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			// The body can echo the prompt, which holds account strings, so it is not included.
			return "", fmt.Errorf("llm http %d", resp.StatusCode)
		}
		var cr chatResponse
		if err := json.Unmarshal(data, &cr); err != nil {
			return "", fmt.Errorf("llm response: %w", err)
		}
		if cr.Error != nil {
			return "", fmt.Errorf("llm error: %s", cr.Error.Message)
		}
		if len(cr.Choices) == 0 {
			return "", fmt.Errorf("llm response had no choices")
		}
		return cr.Choices[0].Message.Content, nil
	}
	return "", lastErr
}
