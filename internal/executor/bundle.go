package executor

import (
	"encoding/json"
	"net/url"
	"regexp"
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

func (b *Bundle) AddSchemaGap(resultIndex int, gap string) {
	if b == nil {
		return
	}
	if resultIndex >= 0 && resultIndex < len(b.Results) {
		b.Results[resultIndex].SchemaGaps = appendUniqueString(b.Results[resultIndex].SchemaGaps, gap)
	}
	if resultIndex >= 0 && resultIndex < len(b.Coverage.Entries) {
		b.Coverage.Entries[resultIndex].SchemaGaps = appendUniqueString(b.Coverage.Entries[resultIndex].SchemaGaps, gap)
	}
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
	out.Request.URL = redactURLString(out.Request.URL)
	out.Request.Headers = redactStringMap(out.Request.Headers)
	out.Request.Metadata = redactStringMap(out.Request.Metadata)
	out.Response.Headers = redactStringMap(out.Response.Headers)
	out.Request.Body = redactedBodySnippet(out.Request.Body)
	out.Response.Body = redactedBodySnippet(out.Response.Body)
	return out
}

var secretValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:eyJ[A-Za-z0-9_-]+)\.(?:[A-Za-z0-9_-]+)\.(?:[A-Za-z0-9_-]+)\b`),
	regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
}

func redactedBodySnippet(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	if redacted, ok := redactJSONBody(body); ok {
		return trimBody(redacted)
	}
	if containsSensitiveValue(string(body)) {
		return []byte("[redacted]")
	}
	return trimBody(body)
}

func trimBody(body []byte) []byte {
	if len(body) > 512 {
		return append(append([]byte(nil), body[:512]...), []byte("...[truncated]")...)
	}
	return append([]byte(nil), body...)
}

func redactJSONBody(body []byte) ([]byte, bool) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, false
	}
	redacted := redactJSONValue(value, "")
	data, err := json.Marshal(redacted)
	if err != nil {
		return nil, false
	}
	return data, true
}

func redactJSONValue(value any, key string) any {
	if isSensitiveName(key) {
		return "[redacted]"
	}
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for childKey, childValue := range v {
			out[childKey] = redactJSONValue(childValue, childKey)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, childValue := range v {
			out[i] = redactJSONValue(childValue, key)
		}
		return out
	case string:
		if containsSensitiveValue(v) {
			return "[redacted]"
		}
	}
	return value
}

func redactStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		if isSensitiveName(key) || containsSensitiveValue(value) {
			out[key] = "[redacted]"
			continue
		}
		out[key] = value
	}
	return out
}

func redactURLString(rawURL string) string {
	if strings.TrimSpace(rawURL) == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		if containsSensitiveValue(rawURL) {
			return "[redacted]"
		}
		return rawURL
	}
	if parsed.User != nil {
		parsed.User = url.User("[redacted]")
	}
	query := parsed.Query()
	changed := false
	for key, values := range query {
		if isSensitiveName(key) {
			query.Set(key, "[redacted]")
			changed = true
			continue
		}
		for i, value := range values {
			if containsSensitiveValue(value) {
				values[i] = "[redacted]"
				changed = true
			}
		}
		query[key] = values
	}
	if changed {
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}

func isSensitiveName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	switch lower {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return true
	}
	for _, marker := range []string{"token", "secret", "password", "passwd", "credential", "api-key", "api_key", "apikey", "access-key", "access_key", "private-key", "private_key", "session", "jwt"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsSensitiveValue(value string) bool {
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin ") && strings.Contains(lower, "private key-----") {
		return true
	}
	for _, pattern := range secretValuePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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
//	write_not_allowed     — mutating operation skipped by read-only safety defaults
//	budget_exceeded       — request budget was exhausted before this operation ran
//	streaming_unsupported — gRPC streaming method, not yet supported
//	schema_gap            — request failed and the seed relied only on type fallbacks
//	bad_status            — server returned a 4xx or 5xx response
//	network_error         — transport-level failure (timeout, connection refused, etc.)
func classifyBlockReason(r Result) string {
	errLower := strings.ToLower(r.Error)
	switch {
	case strings.Contains(errLower, "mutating operation requires explicit write opt-in"):
		return "write_not_allowed"
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
