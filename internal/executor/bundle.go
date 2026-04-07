package executor

import (
	"encoding/json"
	"time"

	"github.com/Shasheen8/Spekto/internal/inventory"
)

type Bundle struct {
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Results    []Result      `json:"results"`
	Summary    BundleSummary `json:"summary"`
}

type BundleSummary struct {
	Total      int            `json:"total"`
	Succeeded  int            `json:"succeeded"`
	Failed     int            `json:"failed"`
	Skipped    int            `json:"skipped"`
	ByProtocol map[string]int `json:"by_protocol,omitempty"`
	ByTarget   map[string]int `json:"by_target,omitempty"`
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
}

func (b Bundle) JSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
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
