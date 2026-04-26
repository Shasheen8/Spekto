package report

import (
	"encoding/json"

	"github.com/Shasheen8/Spekto/internal/executor"
)

// CoverageSummary is the standalone coverage artifact written to --coverage-out.
// It extends the bundle's CoverageReport with per-auth-context breakdowns and
// a deduplicated schema gap list for operator diagnostics.
type CoverageSummary struct {
	TotalOperations   int                       `json:"total_operations"`
	ExecutionAttempts int                       `json:"execution_attempts"`
	Succeeded         int                       `json:"succeeded"`
	Failed            int                       `json:"failed"`
	Skipped           int                       `json:"skipped"`
	CoveragePct       float64                   `json:"coverage_pct"`
	ByProtocol        map[string]ProtoBreakdown `json:"by_protocol,omitempty"`
	ByAuthContext     map[string]AuthBreakdown  `json:"by_auth_context,omitempty"`
	ByReason          map[string]int            `json:"by_reason,omitempty"`
	SchemaGaps        []SchemaGapEntry          `json:"schema_gaps,omitempty"`
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
	coverage := bundle.Coverage
	pct := 0.0
	if coverage.TotalOperations > 0 {
		pct = float64(coverage.Covered) / float64(coverage.TotalOperations) * 100
	}

	byProto := operationCoverageByProtocol(coverage)
	byAuth := map[string]AuthBreakdown{}

	for _, r := range bundle.Results {
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
		TotalOperations:   coverage.TotalOperations,
		ExecutionAttempts: coverage.ExecutionAttempts,
		Succeeded:         coverage.Covered,
		Failed:            coverage.Uncovered,
		Skipped:           bundle.Summary.Skipped,
		CoveragePct:       pct,
		ByProtocol:        byProto,
		ByAuthContext:     byAuth,
		ByReason:          coverage.ByReason,
		SchemaGaps:        gaps,
	}
}

func operationCoverageByProtocol(coverage executor.CoverageReport) map[string]ProtoBreakdown {
	type operationState struct {
		protocol string
		status   string
	}
	states := map[string]operationState{}
	for _, entry := range coverage.Entries {
		key := entry.Target + "|" + entry.OperationID
		state := states[key]
		if state.protocol == "" {
			state.protocol = entry.Protocol
			state.status = entry.Status
		}
		if entry.Status == "succeeded" {
			state.status = "succeeded"
		} else if state.status == "" {
			state.status = entry.Status
		}
		states[key] = state
	}
	byProto := map[string]ProtoBreakdown{}
	for _, state := range states {
		pb := byProto[state.protocol]
		pb.Total++
		switch state.status {
		case "succeeded":
			pb.Succeeded++
		case "skipped":
			pb.Skipped++
		default:
			pb.Failed++
		}
		byProto[state.protocol] = pb
	}
	return byProto
}

// JSON serialises the summary as indented JSON.
func (c CoverageSummary) JSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
