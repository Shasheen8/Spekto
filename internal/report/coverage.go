package report

import (
	"encoding/json"

	"github.com/Shasheen8/Spekto/internal/executor"
)

// CoverageSummary is the standalone coverage artifact written to --coverage-out.
// It extends the bundle's CoverageReport with per-auth-context breakdowns and
// a deduplicated schema gap list for operator diagnostics.
type CoverageSummary struct {
	TotalOperations int                        `json:"total_operations"`
	Succeeded       int                        `json:"succeeded"`
	Failed          int                        `json:"failed"`
	Skipped         int                        `json:"skipped"`
	CoveragePct     float64                    `json:"coverage_pct"`
	ByProtocol      map[string]ProtoBreakdown  `json:"by_protocol,omitempty"`
	ByAuthContext   map[string]AuthBreakdown   `json:"by_auth_context,omitempty"`
	ByReason        map[string]int             `json:"by_reason,omitempty"`
	SchemaGaps      []SchemaGapEntry           `json:"schema_gaps,omitempty"`
}

// ProtoBreakdown aggregates coverage counts for a single protocol.
type ProtoBreakdown struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
}

// AuthBreakdown aggregates coverage counts for a single auth context.
type AuthBreakdown struct {
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
}

// SchemaGapEntry identifies an operation where the seed generator fell back to
// type-based placeholders because no real example or resource hint was available.
type SchemaGapEntry struct {
	OperationID string   `json:"operation_id"`
	Locator     string   `json:"locator"`
	Gaps        []string `json:"gaps"`
}

// BuildCoverageSummary derives a CoverageSummary from a completed scan bundle.
func BuildCoverageSummary(bundle executor.Bundle) CoverageSummary {
	s := bundle.Summary
	pct := 0.0
	if s.Total > 0 {
		pct = float64(s.Succeeded) / float64(s.Total) * 100
	}

	byProto := map[string]ProtoBreakdown{}
	byAuth := map[string]AuthBreakdown{}

	for _, r := range bundle.Results {
		proto := string(r.Protocol)
		pb := byProto[proto]
		pb.Total++
		switch r.Status {
		case "succeeded":
			pb.Succeeded++
		case "skipped":
			pb.Skipped++
		default:
			pb.Failed++
		}
		byProto[proto] = pb

		if r.AuthContextName != "" {
			ab := byAuth[r.AuthContextName]
			switch r.Status {
			case "succeeded":
				ab.Succeeded++
			case "skipped":
				ab.Skipped++
			default:
				ab.Failed++
			}
			byAuth[r.AuthContextName] = ab
		}
	}

	// Deduplicate schema gaps by operation — multiple auth contexts may produce
	// the same gaps for the same operation.
	seen := map[string]bool{}
	var gaps []SchemaGapEntry
	for _, entry := range bundle.Coverage.Entries {
		if len(entry.SchemaGaps) == 0 || seen[entry.OperationID] {
			continue
		}
		seen[entry.OperationID] = true
		gaps = append(gaps, SchemaGapEntry{
			OperationID: entry.OperationID,
			Locator:     entry.Locator,
			Gaps:        entry.SchemaGaps,
		})
	}

	return CoverageSummary{
		TotalOperations: s.Total,
		Succeeded:       s.Succeeded,
		Failed:          s.Failed,
		Skipped:         s.Skipped,
		CoveragePct:     pct,
		ByProtocol:      byProto,
		ByAuthContext:   byAuth,
		ByReason:        bundle.Coverage.ByReason,
		SchemaGaps:      gaps,
	}
}

// JSON serialises the summary as indented JSON.
func (c CoverageSummary) JSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
