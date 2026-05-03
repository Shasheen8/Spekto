package enrichment

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/rules"
)

type FindingEnrichment struct {
	FindingID          string   `json:"finding_id"`
	RuleID             string   `json:"rule_id"`
	Summary            string   `json:"summary"`
	Impact             string   `json:"impact"`
	ExploitNarrative   string   `json:"exploit_narrative"`
	FixSteps           []string `json:"fix_steps"`
	ValidationSteps    []string `json:"validation_steps"`
	FalsePositiveNotes string   `json:"false_positive_notes"`
	References         []string `json:"references"`
	Model              string   `json:"model"`
	GeneratedAt        string   `json:"generated_at"`
}

type EnrichmentError struct {
	FindingID string `json:"finding_id"`
	RuleID    string `json:"rule_id"`
	Error     string `json:"error"`
}

type EnrichedFindingSet struct {
	Findings      []rules.Finding     `json:"findings"`
	Enrichments   []FindingEnrichment `json:"enrichments"`
	Errors        []EnrichmentError   `json:"errors,omitempty"`
	ModelUsed     string              `json:"model_used"`
	EnrichedCount int                 `json:"enriched_count"`
	ErrorCount    int                 `json:"error_count"`
	SkippedCount  int                 `json:"skipped_count"`
	GeneratedAt   string              `json:"generated_at"`
}

func (s EnrichedFindingSet) JSON() ([]byte, error) {
	return jsonMarshalIndent(s)
}

type EnrichmentInput struct {
	FindingID            string `json:"finding_id"`
	RuleID               string `json:"rule_id"`
	Severity             string `json:"severity"`
	Confidence           string `json:"confidence"`
	Title                string `json:"title"`
	Description          string `json:"description"`
	Remediation          string `json:"remediation"`
	OWASP                string `json:"owasp,omitempty"`
	CWE                  int    `json:"cwe,omitempty"`
	Protocol             string `json:"protocol"`
	Method               string `json:"method,omitempty"`
	Endpoint             string `json:"endpoint,omitempty"`
	OperationID          string `json:"operation_id,omitempty"`
	AuthContextName      string `json:"auth_context_name,omitempty"`
	SeedStatusCode       int    `json:"seed_status_code,omitempty"`
	ProbeStatusCode      int    `json:"probe_status_code,omitempty"`
	SeedResponseSnippet  string `json:"seed_response_snippet,omitempty"`
	ProbeResponseSnippet string `json:"probe_response_snippet,omitempty"`
}

type Provider interface {
	Enrich(findings []rules.Finding, opts EnrichOptions) EnrichedFindingSet
}

type EnrichOptions struct {
	MaxFindings    int
	Model          string
	Timeout        time.Duration
	InputBodyLimit int
}

type NopProvider struct{}

func (NopProvider) Enrich(findings []rules.Finding, _ EnrichOptions) EnrichedFindingSet {
	return EnrichedFindingSet{
		Findings:     findings,
		SkippedCount: len(findings),
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

const defaultBodyLimit = 500

func BuildEnrichmentInputs(findings []rules.Finding, bodyLimit int) []EnrichmentInput {
	if bodyLimit <= 0 {
		bodyLimit = defaultBodyLimit
	}
	inputs := make([]EnrichmentInput, 0, len(findings))
	for _, f := range findings {
		input := EnrichmentInput{
			FindingID:       f.ID,
			RuleID:          f.RuleID,
			Severity:        string(f.Severity),
			Confidence:      string(f.Confidence),
			Title:           f.Title,
			Description:     f.Description,
			Remediation:     f.Remediation,
			OWASP:           f.OWASP,
			CWE:             f.CWE,
			Protocol:        string(f.Protocol),
			OperationID:     f.OperationID,
			AuthContextName: f.AuthContextName,
		}
		if f.Evidence.Seed.Request.Method != "" {
			input.Method = f.Evidence.Seed.Request.Method
		}
		endpoint := f.Evidence.Seed.Request.URL
		if endpoint == "" && f.Evidence.Probe != nil {
			endpoint = f.Evidence.Probe.Request.URL
		}
		input.Endpoint = redactURLForEnrichment(endpoint)
		input.SeedStatusCode = f.Evidence.Seed.Response.StatusCode
		input.SeedResponseSnippet = truncateBytes(f.Evidence.Seed.Response.Body, bodyLimit)
		if f.Evidence.Probe != nil {
			input.ProbeStatusCode = f.Evidence.Probe.Response.StatusCode
			input.ProbeResponseSnippet = truncateBytes(f.Evidence.Probe.Response.Body, bodyLimit)
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func truncateBytes(s []byte, limit int) string {
	if limit <= 0 || len(s) == 0 {
		return ""
	}
	if len(s) <= limit {
		return string(s)
	}
	return string(s[:limit]) + "...[truncated]"
}

func redactURLForEnrichment(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func DedupeFindingsByID(findings []rules.Finding) []rules.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		out = append(out, f)
	}
	return out
}

var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

func PrioritizeFindings(findings []rules.Finding, maxFindings int) []rules.Finding {
	if maxFindings <= 0 || len(findings) <= maxFindings {
		return findings
	}
	prioritized := make([]rules.Finding, len(findings))
	copy(prioritized, findings)
	slices.SortFunc(prioritized, func(a, b rules.Finding) int {
		ai, ok := severityOrder[strings.ToLower(string(a.Severity))]
		if !ok {
			ai = 99
		}
		bi, ok := severityOrder[strings.ToLower(string(b.Severity))]
		if !ok {
			bi = 99
		}
		return ai - bi
	})
	return prioritized[:maxFindings]
}

var (
	reAWSKey     = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	rePrivateKey = regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----`)
	reJWT        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
)

func scrubEnrichmentOutput(s string) string {
	s = reAWSKey.ReplaceAllString(s, "[redacted-aws-key]")
	s = rePrivateKey.ReplaceAllString(s, "[redacted-private-key]")
	s = reJWT.ReplaceAllString(s, "[redacted-jwt]")
	return s
}

func capStringLength(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "..."
}

func capSliceLength(items []string, maxItems int, maxItemLen int) []string {
	if len(items) > maxItems {
		items = items[:maxItems]
	}
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = capStringLength(item, maxItemLen)
	}
	return out
}

func jsonMarshalIndent(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
