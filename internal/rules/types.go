package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// Severity classifies the impact of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Confidence classifies how certain the rule is about the finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Finding is a confirmed security issue produced by a rule check.
type Finding struct {
	ID              string             `json:"id"`
	RuleID          string             `json:"rule_id"`
	Severity        Severity           `json:"severity"`
	Confidence      Confidence         `json:"confidence"`
	Title           string             `json:"title"`
	Description     string             `json:"description"`
	Target          string             `json:"target"`
	Protocol        inventory.Protocol `json:"protocol"`
	OperationID     string             `json:"operation_id"`
	Locator         string             `json:"locator"`
	AuthContextName string             `json:"auth_context_name,omitempty"`
	OWASP           string             `json:"owasp,omitempty"`
	CWE             int                `json:"cwe,omitempty"`
	Evidence        FindingEvidence    `json:"evidence"`
	Remediation     string             `json:"remediation,omitempty"`
	FoundAt         time.Time          `json:"found_at"`
}

// FindingEvidence carries the request/response pair that confirms the finding.
// Seed is the successful baseline. Probe is the mutated request that triggered it.
// Probe is nil for response-analysis-only rules (e.g. security headers).
type FindingEvidence struct {
	Seed  executor.Evidence  `json:"seed"`
	Probe *executor.Evidence `json:"probe,omitempty"`
}

// Probe is a mutation to send and an evaluator to assess the response.
// The Evaluate closure captures the seed via its enclosing Check call.
type Probe struct {
	RuleID   string
	Request  executor.HTTPRequest
	Evaluate func(result executor.HTTPResult) []Finding
}

// Rule is a single security check. Check receives a successful seed result and
// the resolved auth context used for that seed. It returns zero or more Probes
// to execute, and zero or more immediate Findings determinable from the seed
// response alone (no additional request required).
type Rule interface {
	ID() string
	Check(seed executor.Result, authCtx auth.Context) (probes []Probe, findings []Finding)
}

// FindingSet is the top-level output written to the findings file.
type FindingSet struct {
	Findings []Finding      `json:"findings"`
	Summary  FindingSummary `json:"summary"`
}

// FindingSummary aggregates counts for quick reporting.
type FindingSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	ByRule     map[string]int `json:"by_rule,omitempty"`
}

// Summarize computes the FindingSummary from a slice of findings.
func Summarize(findings []Finding) FindingSummary {
	s := FindingSummary{
		Total:      len(findings),
		BySeverity: map[string]int{},
		ByRule:     map[string]int{},
	}
	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		s.ByRule[f.RuleID]++
	}
	return s
}

// findingID returns a stable, deterministic ID for a (rule, operation) pair.
func findingID(ruleID, operationID string) string {
	key := strings.ToLower(ruleID + "|" + operationID)
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%s-%s", ruleID, hex.EncodeToString(sum[:4]))
}

// seedBaseRequest builds a probe request pre-populated with the seed's method,
// URL, body, and content type. The caller applies any mutation on top.
func seedBaseRequest(seed executor.Result) executor.HTTPRequest {
	return executor.HTTPRequest{
		Method:      seed.Evidence.Request.Method,
		URL:         seed.Evidence.Request.URL,
		Body:        seed.Evidence.Request.Body,
		ContentType: seed.Evidence.Request.ContentType,
	}
}

// probeID returns a unique request ID for a probe so it can be correlated in logs.
func probeID(seed executor.Result, ruleID string) string {
	return seed.OperationID + ":probe:" + ruleID
}

// cloneNonRedactedHeaders copies seed request headers, skipping [redacted] values
// so we don't forward placeholder strings to the probe target.
func cloneNonRedactedHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if v != "[redacted]" {
			out[k] = v
		}
	}
	return out
}

// probeSucceeded returns true when the probe got a 2xx or 3xx response.
func probeSucceeded(result executor.HTTPResult) bool {
	return result.Error == "" && result.StatusCode >= 200 && result.StatusCode < 400
}

// probeEvidence wraps an HTTPResult as FindingEvidence.Probe.
func probeEvidence(result executor.HTTPResult) *executor.Evidence {
	return &executor.Evidence{
		Request: executor.RequestEvidence{
			Method:      result.Method,
			URL:         result.URL,
			Headers:     result.RequestHeaders,
			ContentType: result.RequestContentType,
			Body:        result.RequestBody,
		},
		Response: executor.ResponseEvidence{
			StatusCode: result.StatusCode,
			Headers:    result.ResponseHeaders,
			Body:       result.ResponseBody,
			Truncated:  result.Truncated,
		},
	}
}

// newFinding constructs a Finding from the common fields every rule provides.
func newFinding(
	ruleID string,
	severity Severity,
	confidence Confidence,
	title, description string,
	seed executor.Result,
	evidence FindingEvidence,
	owasp string,
	cwe int,
	remediation string,
) Finding {
	return Finding{
		ID:              findingID(ruleID, seed.OperationID),
		RuleID:          ruleID,
		Severity:        severity,
		Confidence:      confidence,
		Title:           title,
		Description:     description,
		Target:          seed.Target,
		Protocol:        seed.Protocol,
		OperationID:     seed.OperationID,
		Locator:         seed.Locator,
		AuthContextName: seed.AuthContextName,
		OWASP:           owasp,
		CWE:             cwe,
		Evidence:        evidence,
		Remediation:     remediation,
		FoundAt:         time.Now().UTC(),
	}
}
