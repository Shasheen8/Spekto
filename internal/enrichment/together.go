package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/rules"
	together "github.com/togethercomputer/together-go"
	"github.com/togethercomputer/together-go/option"
	"github.com/togethercomputer/together-go/packages/param"
)

const DefaultModel = "Qwen/Qwen3-Coder-Next-FP8"
const defaultMaxTokens = 4096
const defaultTemperature = 0.2

type TogetherProvider struct {
	client together.Client
}

func NewTogetherProvider(apiKey string) *TogetherProvider {
	return &TogetherProvider{client: together.NewClient(option.WithAPIKey(apiKey))}
}

func (p *TogetherProvider) Enrich(findings []rules.Finding, opts EnrichOptions) EnrichedFindingSet {
	now := time.Now().UTC().Format(time.RFC3339)
	deduped := DedupeFindingsByID(findings)
	redacted := rules.RedactFindings(deduped)
	prioritized := PrioritizeFindings(redacted, opts.MaxFindings)

	result := EnrichedFindingSet{
		Findings:    redacted,
		ModelUsed:   effectiveModel(opts.Model),
		GeneratedAt: now,
	}

	inputs := BuildEnrichmentInputs(prioritized, opts.InputBodyLimit)
	totalTimeout := effectiveTimeout(opts.Timeout)
	n := maxInt(len(inputs), 1)
	perFinding := totalTimeout / time.Duration(n)
	if perFinding < 5*time.Second {
		perFinding = 5 * time.Second
	}

	for _, input := range inputs {
		ctx, cancel := context.WithTimeout(context.Background(), perFinding)
		enh, err := p.enrichOne(ctx, input, opts)
		cancel()
		if err != nil {
			result.Errors = append(result.Errors, EnrichmentError{
				FindingID: input.FindingID,
				RuleID:    input.RuleID,
				Error:     scrubEnrichmentOutput(err.Error()),
			})
			continue
		}
		result.Enrichments = append(result.Enrichments, enh)
	}

	result.EnrichedCount = len(result.Enrichments)
	result.ErrorCount = len(result.Errors)
	result.SkippedCount = len(deduped) - result.EnrichedCount - result.ErrorCount
	return result
}

func (p *TogetherProvider) enrichOne(ctx context.Context, input EnrichmentInput, opts EnrichOptions) (FindingEnrichment, error) {
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return FindingEnrichment{}, fmt.Errorf("marshal input: %w", err)
	}

	model := effectiveModel(opts.Model)

	resp, err := p.client.Chat.Completions.New(ctx, together.ChatCompletionNewParams{
		Model:       model,
		Messages:    buildMessages(inputJSON),
		MaxTokens:   param.NewOpt(int64(defaultMaxTokens)),
		Temperature: param.NewOpt(defaultTemperature),
	})
	if err != nil {
		return FindingEnrichment{}, formatAPIError(err)
	}
	if len(resp.Choices) == 0 {
		return FindingEnrichment{}, fmt.Errorf("together api: no choices returned (model %s may not support this request)", model)
	}

	msg := resp.Choices[0].Message
	content := msg.Content
	if strings.TrimSpace(content) == "" {
		content = msg.Reasoning
	}
	if strings.TrimSpace(content) == "" {
		return FindingEnrichment{}, fmt.Errorf("together api: empty content and reasoning in response")
	}

	enh, err := parseEnrichmentJSON(content)
	if err != nil {
		return FindingEnrichment{}, fmt.Errorf("parse enrichment: %w", err)
	}
	enh.FindingID = input.FindingID
	enh.RuleID = input.RuleID
	enh.Model = model
	enh.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	enh.Summary = scrubEnrichmentOutput(capStringLength(enh.Summary, 1000))
	enh.Impact = scrubEnrichmentOutput(capStringLength(enh.Impact, 1000))
	enh.ExploitNarrative = scrubEnrichmentOutput(capStringLength(enh.ExploitNarrative, 1000))
	enh.FalsePositiveNotes = scrubEnrichmentOutput(capStringLength(enh.FalsePositiveNotes, 1000))
	enh.FixSteps = scrubSlice(enh.FixSteps, 10, 500)
	enh.ValidationSteps = scrubSlice(enh.ValidationSteps, 10, 500)
	enh.References = scrubSlice(enh.References, 10, 500)
	return enh, nil
}

func buildMessages(inputJSON []byte) []together.ChatCompletionNewParamsMessageUnion {
	return []together.ChatCompletionNewParamsMessageUnion{
		{
			OfChatCompletionNewsMessageChatCompletionSystemMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionSystemMessageParam{
				Content: systemPrompt(),
				Role:    "system",
			},
		},
		{
			OfChatCompletionNewsMessageChatCompletionUserMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionUserMessageParam{
				Content: together.ChatCompletionNewParamsMessageChatCompletionUserMessageParamContentUnion{
					OfString: param.NewOpt(string(inputJSON)),
				},
				Role: "user",
			},
		},
	}
}

func systemPrompt() string {
	return `You are a security analysis assistant. You enrich API security findings with context.

Rules:
- Never invent evidence or details not present in the input.
- Do not upgrade or downgrade the severity or confidence of the finding.
- If you are uncertain, say so plainly.
- Keep remediation actionable and specific to the provided endpoint and rule.
- Never include secrets, tokens, passwords, or API keys in your output.

Respond with ONLY a JSON object (no markdown fences, no explanation before or after) with these fields:
- summary: one-sentence plain-language summary
- impact: real-world impact if exploited
- exploit_narrative: brief narrative of how an attacker could exploit this
- fix_steps: ordered array of fix/mitigation steps
- validation_steps: ordered array of steps to validate the fix
- false_positive_notes: notes on why this could be a false positive
- references: array of relevant OWASP, CWE, or security reference URLs`
}

var reJSONBlock = regexp.MustCompile("(?s)```(?:json)?\\s*\\n(.*?)\\n```")

func parseEnrichmentJSON(content string) (FindingEnrichment, error) {
	raw := strings.TrimSpace(content)

	if loc := reJSONBlock.FindStringIndex(raw); loc != nil {
		raw = strings.TrimSpace(raw[loc[0]+3:])
		if end := strings.Index(raw, "```"); end != -1 {
			raw = strings.TrimSpace(raw[:end])
		}
	}

	start := strings.Index(raw, "{")
	if start == -1 {
		return FindingEnrichment{}, fmt.Errorf("no JSON object found in response")
	}
	end := strings.LastIndex(raw, "}")
	if end == -1 || end <= start {
		return FindingEnrichment{}, fmt.Errorf("incomplete JSON object in response")
	}
	raw = raw[start : end+1]

	var enh FindingEnrichment
	if err := json.Unmarshal([]byte(raw), &enh); err != nil {
		return FindingEnrichment{}, fmt.Errorf("invalid JSON: %w (first 200 chars: %s)", err, truncateString(raw, 200))
	}
	return enh, nil
}

func formatAPIError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "model_not_available") || strings.Contains(msg, "Unable to access") {
		return fmt.Errorf("together api: model not available on serverless tier; set --ai-model to a supported model (see https://api.together.ai/models): %s", scrubEnrichmentOutput(msg))
	}
	if strings.Contains(msg, "streaming_required") || strings.Contains(msg, "only supports streaming") {
		return fmt.Errorf("together api: model requires streaming which is not supported for enrichment; use a non-streaming model like Qwen/Qwen3-Coder-Next-FP8")
	}
	if strings.Contains(msg, "invalid_api_key") || strings.Contains(msg, "Unauthorized") {
		return fmt.Errorf("together api: invalid API key; check %s", "TOGETHER_API_KEY")
	}
	return fmt.Errorf("together api: %s", scrubEnrichmentOutput(msg))
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func scrubSlice(items []string, maxItems int, maxItemLen int) []string {
	capped := capSliceLength(items, maxItems, maxItemLen)
	out := make([]string, len(capped))
	for i, item := range capped {
		out[i] = scrubEnrichmentOutput(item)
	}
	return out
}

func effectiveModel(model string) string {
	if m := strings.TrimSpace(model); m != "" {
		return m
	}
	return DefaultModel
}

func effectiveTimeout(timeout time.Duration) time.Duration {
	if timeout > 0 {
		return timeout
	}
	return 30 * time.Second
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func CriticalFindings(findings []rules.Finding) []rules.Finding {
	var out []rules.Finding
	for _, f := range findings {
		if f.Severity == rules.SeverityCritical {
			out = append(out, f)
		}
	}
	return out
}
