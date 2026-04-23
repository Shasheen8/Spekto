package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/rules"
)

const divider = "────────────────────────────────────────────────────────────"

// PrintSummary writes a human-readable scan summary to w (typically os.Stderr).
// It covers coverage, findings by severity, and schema gap hints.
func PrintSummary(w io.Writer, bundle executor.Bundle, findings []rules.Finding) {
	fmt.Fprintln(w, divider)
	fmt.Fprintln(w, "Spekto scan complete")
	fmt.Fprintln(w, divider)

	// Coverage line.
	s := bundle.Summary
	pct := 0.0
	if s.Total > 0 {
		pct = float64(s.Succeeded) / float64(s.Total) * 100
	}
	fmt.Fprintf(w, "Coverage  %d/%d operations seeded (%.0f%%)\n", s.Succeeded, s.Total, pct)

	// Per-protocol breakdown.
	protos := make([]string, 0, len(s.ByProtocol))
	for p := range s.ByProtocol {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, proto := range protos {
		succForProto := 0
		for _, r := range bundle.Results {
			if string(r.Protocol) == proto && r.Status == "succeeded" {
				succForProto++
			}
		}
		fmt.Fprintf(w, "  %-9s %d/%d\n", proto+":", succForProto, s.ByProtocol[proto])
	}

	// Block reasons.
	if len(bundle.Coverage.ByReason) > 0 {
		reasons := make([]string, 0, len(bundle.Coverage.ByReason))
		for reason, count := range bundle.Coverage.ByReason {
			reasons = append(reasons, fmt.Sprintf("%s:%d", reason, count))
		}
		sort.Strings(reasons)
		fmt.Fprintf(w, "  Blocked   %s\n", strings.Join(reasons, "  "))
	}

	// Findings.
	fmt.Fprintf(w, "\nFindings  %d total\n", len(findings))
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintf(w, "  %-10s %-8s %-38s %s\n",
				strings.ToUpper(string(f.Severity)),
				f.RuleID,
				truncate(f.Title, 38),
				f.Locator,
			)
		}
	}

	// Schema gap hint.
	gapOps := 0
	seen := map[string]bool{}
	for _, entry := range bundle.Coverage.Entries {
		if len(entry.SchemaGaps) > 0 && !seen[entry.OperationID] {
			seen[entry.OperationID] = true
			gapOps++
		}
	}
	if gapOps > 0 {
		fmt.Fprintf(w, "\nHint  %d operation(s) used type fallbacks — add resource_hints to improve seed quality\n", gapOps)
	}

	fmt.Fprintln(w, divider)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
