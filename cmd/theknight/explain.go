package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Yeagerist0/theknight/pkg/explain"
	"github.com/Yeagerist0/theknight/pkg/rules"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// providerFromEnv builds the model client. Credentials come from the
// environment only, never from a flag.
func providerFromEnv() (*explain.LLM, error) {
	key := os.Getenv("THEKNIGHT_LLM_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("--explain requires THEKNIGHT_LLM_API_KEY (any OpenAI-compatible endpoint; set THEKNIGHT_LLM_BASE_URL and THEKNIGHT_LLM_MODEL to change the defaults)")
	}
	retries, _ := strconv.Atoi(os.Getenv("THEKNIGHT_LLM_RETRIES"))
	return &explain.LLM{
		Retries:         retries, // 0 keeps the default (2); raise it for providers with tight per-minute limits
		BaseURL:         envOr("THEKNIGHT_LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"),
		APIKey:          key,
		Model:           envOr("THEKNIGHT_LLM_MODEL", "gemini-3.1-flash-lite"),
		ReasoningEffort: envOr("THEKNIGHT_LLM_REASONING_EFFORT", "none"),
	}, nil
}

// briefAndReport asks for a briefing and tells the operator on stderr when the
// model's text was not used and why, so a silent fallback never hides a problem.
func briefAndReport(ctx context.Context, p explain.Provider, f rules.Finding, fallback string, errOut io.Writer) explain.Result {
	res := explain.Brief(ctx, p, f, fallback)
	switch {
	case res.Err != nil:
		fmt.Fprintf(errOut, "note: no AI briefing for %s (%s): %v\n", f.RuleID, f.Resource.ID, res.Err)
	case res.Rejection != nil:
		fmt.Fprintf(errOut, "note: AI briefing for %s (%s) rejected (%s); using the template explanation\n", f.RuleID, f.Resource.ID, res.Rejection.Reason)
	}
	return res
}
