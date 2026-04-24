package executor

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/inventory"
)

type Bundle struct {
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Results    []Result       `json:"results"`
	Summary    BundleSummary  `json:"summary"`
	Coverage   CoverageReport `json:"coverage"`
}

type BundleSummary struct {
	Total      int            `json:"total"`
	Succeeded  int            `json:"succeeded"`
	Failed     int            `json:"failed"`
	Skipped    int            `json:"skipped"`
	ByProtocol map[string]int `json:"by_protocol,omitempty"`
	ByTarget   map[string]int `json:"by_target,omitempty"`
}

// CoverageReport explains why each operation did or did not succeed.
// It is intended to give operators clear signal on what is blocking coverage.
type CoverageReport struct {
	TotalOperations   int             `json:"total_operations"`
	ExecutionAttempts int             `json:"execution_attempts"`
	Covered           int             `json:"covered"`
	Uncovered         int             `json:"uncovered"`
	ByReason          map[string]int  `json:"by_reason,omitempty"`
	Entries           []CoverageEntry `json:"entries,omitempty"`
}

// CoverageEntry is one line of the coverage report for a single (operation, auth context) pair.
type CoverageEntry struct {
	OperationID     string   `json:"operation_id"`
	Locator         string   `json:"locator"`
	Protocol        string   `json:"protocol"`
	Target          string   `json:"target"`
	AuthContextName string   `json:"auth_context_name,omitempty"`
	Status          string   `json:"status"`
	BlockReason     string   `json:"block_reason,omitempty"`
	SchemaGaps      []string `json:"schema_gaps,omitempty"`
}

type Result struct {
	Protocol        inventory.Protocol `json:"protocol"`
	Target          string             `json:"target"`
	OperationID     string             `json:"operation_id"`
	Locator         string             `json:"locator"`
	DisplayName     string             `json:"display_name"`
	AuthContextName string             `json:"auth_context_name,omitempty"`
	Status          string             `json:"status"`
	Error           string             `json:"error,omitempty"`
	SchemaGaps      []string           `json:"schema_gaps,omitempty"`
	StartedAt       time.Time          `json:"started_at"`
	Duration        time.Duration      `json:"duration"`
	Evidence        Evidence           `json:"evidence"`
}

type Evidence struct {
	Request  RequestEvidence  `json:"request"`
	Response ResponseEvidence `json:"response"`
}

type RequestEvidence struct {
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        []byte            `json:"body,omitempty"`
	GRPCMethod  string            `json:"grpc_method,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ResponseEvidence struct {
	StatusCode int               `json:"status_code,omitempty"`
	GRPCCode   string            `json:"grpc_code,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       []byte            `json:"body,omitempty"`
	Truncated  bool              `json:"truncated,omitempty"`
}

func (b *Bundle) Finalize() {
	b.Summary = summarizeResults(b.Results)
	b.Coverage = buildCoverageReport(b.Results)
}

func (b Bundle) JSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

func (b Bundle) RedactedJSON() ([]byte, error) {
	redacted := b
	redacted.Results = make([]Result, len(b.Results))
	for i, result := range b.Results {
		redacted.Results[i] = result.Redacted()
	}
	return json.MarshalIndent(redacted, "", "  ")
}

func (r Result) Redacted() Result {
	out := r
	out.Evidence = out.Evidence.Redacted()
	return out
}

func (e Evidence) Redacted() Evidence {
	out := e
	out.Request.Body = redactedBodySnippet(out.Request.Body)
	out.Response.Body = redactedBodySnippet(out.Response.Body)
	return out
}

func redactedBodySnippet(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	text := strings.ToLower(string(body))
	for _, marker := range []string{"token", "secret", "password", "credential", "api_key", "apikey", "access_key", "private_key"} {
		if strings.Contains(text, marker) {
			return []byte("[redacted]")
		}
	}
	if len(body) > 512 {
		return append(append([]byte(nil), body[:512]...), []byte("...[truncated]")...)
	}
	return append([]byte(nil), body...)
}

func summarizeResults(results []Result) BundleSummary {
	summary := BundleSummary{
		Total:      len(results),
		ByProtocol: map[string]int{},
		ByTarget:   map[string]int{},
	}
	for _, result := range results {
		summary.ByProtocol[string(result.Protocol)]++
		summary.ByTarget[result.Target]++
		switch result.Status {
		case "succeeded":
			summary.Succeeded++
		case "skipped":
			summary.Skipped++
		default:
			summary.Failed++
		}
	}
	return summary
}

// buildCoverageReport classifies each result by block reason and assembles the report.
func buildCoverageReport(results []Result) CoverageReport {
	report := CoverageReport{
		ExecutionAttempts: len(results),
		ByReason:          map[string]int{},
		Entries:           make([]CoverageEntry, 0, len(results)),
	}
	operationStatus := map[string]string{}
	for _, r := range results {
		key := r.Target + "|" + r.OperationID
		if r.Status == "succeeded" {
			operationStatus[key] = "succeeded"
		} else if operationStatus[key] == "" {
			operationStatus[key] = "uncovered"
		}
		entry := CoverageEntry{
			OperationID:     r.OperationID,
			Locator:         r.Locator,
			Protocol:        string(r.Protocol),
			Target:          r.Target,
			AuthContextName: r.AuthContextName,
			Status:          r.Status,
			SchemaGaps:      r.SchemaGaps,
		}
		if r.Status != "succeeded" {
			entry.BlockReason = classifyBlockReason(r)
			report.ByReason[entry.BlockReason]++
		}
		report.Entries = append(report.Entries, entry)
	}
	report.TotalOperations = len(operationStatus)
	for _, status := range operationStatus {
		if status == "succeeded" {
			report.Covered++
		} else {
			report.Uncovered++
		}
	}
	return report
}

// classifyBlockReason maps a failed or skipped result to a human-readable block reason.
// Reasons (in match priority order):
//
//	auth_missing          — no matching auth context was available
//	budget_exceeded       — request budget was exhausted before this operation ran
//	streaming_unsupported — gRPC streaming method, not yet supported
//	schema_gap            — request failed and the seed relied only on type fallbacks
//	bad_status            — server returned a 4xx or 5xx response
//	network_error         — transport-level failure (timeout, connection refused, etc.)
func classifyBlockReason(r Result) string {
	errLower := strings.ToLower(r.Error)
	switch {
	case strings.Contains(errLower, "auth") || strings.Contains(errLower, "no matching auth"):
		return "auth_missing"
	case strings.Contains(errLower, "request budget"):
		return "budget_exceeded"
	case strings.Contains(errLower, "streaming"):
		return "streaming_unsupported"
	}
	// Schema gap: seed used only type fallbacks and server rejected the request.
	if len(r.SchemaGaps) > 0 && r.Evidence.Response.StatusCode >= 400 && r.Evidence.Response.StatusCode < 500 {
		return "schema_gap"
	}
	if r.Evidence.Response.StatusCode >= 400 {
		return "bad_status"
	}
	if r.Evidence.Response.GRPCCode != "" && r.Evidence.Response.GRPCCode != "OK" {
		return "bad_status"
	}
	return "network_error"
}
