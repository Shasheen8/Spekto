package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/Shasheen8/Spekto/internal/rules"
)

const divider = "────────────────────────────────────────────────────────────"

type Artifact struct {
	Kind string
	Path string
}

type SummaryOptions struct {
	RulesSkipped bool
	Artifacts    []Artifact
}

// PrintSummary writes a human-readable scan summary to w (typically os.Stderr).
// It covers coverage, findings by severity, and schema gap hints.
func PrintSummary(w io.Writer, bundle executor.Bundle, findings []rules.Finding) {
	PrintSummaryWithOptions(w, bundle, findings, SummaryOptions{})
}

func PrintSummaryWithOptions(w io.Writer, bundle executor.Bundle, findings []rules.Finding, opts SummaryOptions) {
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

	// Per-protocol breakdown — build succeeded counts in one pass.
	succByProto := make(map[string]int, len(s.ByProtocol))
	for _, r := range bundle.Results {
		if r.Status == "succeeded" {
			succByProto[string(r.Protocol)]++
		}
	}
	protos := make([]string, 0, len(s.ByProtocol))
	for p := range s.ByProtocol {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, proto := range protos {
		fmt.Fprintf(w, "  %-9s %d/%d\n", proto+":", succByProto[proto], s.ByProtocol[proto])
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

	if opts.RulesSkipped {
		fmt.Fprintln(w, "\nRules     skipped (--no-rules)")
	}

	if len(opts.Artifacts) > 0 {
		artifacts := append([]Artifact(nil), opts.Artifacts...)
		sort.Slice(artifacts, func(i, j int) bool {
			if artifacts[i].Kind == artifacts[j].Kind {
				return artifacts[i].Path < artifacts[j].Path
			}
			return artifacts[i].Kind < artifacts[j].Kind
		})
		fmt.Fprintln(w, "\nArtifacts")
		for _, artifact := range artifacts {
			fmt.Fprintf(w, "  %-10s %s\n", artifact.Kind+":", artifact.Path)
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

func PrintDiscoverySummary(w io.Writer, inv inventory.Inventory, artifactPath string) {
	fmt.Fprintln(w, divider)
	fmt.Fprintln(w, "Spekto discovery complete")
	fmt.Fprintln(w, divider)
	fmt.Fprintf(w, "Inventory  %d operations\n", inv.Summary.Total)

	protocols := make([]string, 0, len(inv.Summary.ByProtocol))
	for protocol := range inv.Summary.ByProtocol {
		protocols = append(protocols, protocol)
	}
	sort.Strings(protocols)
	for _, protocol := range protocols {
		fmt.Fprintf(w, "  %-9s %d\n", protocol+":", inv.Summary.ByProtocol[protocol])
	}

	fmt.Fprintf(w, "\nSources   specified=%d observed=%d active=%d manual=%d\n",
		inv.Summary.SpecifiedCount,
		inv.Summary.ObservedCount,
		inv.Summary.ActiveCount,
		inv.Summary.ManualCount,
	)

	if methods := discoveryMethodCounts(inv.Operations); len(methods) > 0 {
		fmt.Fprintln(w, "\nMethods")
		for _, method := range methods {
			fmt.Fprintf(w, "  %-8s %d\n", method.Name, method.Count)
		}
	}

	fmt.Fprintln(w, "\nOperations")
	for _, op := range inv.Operations {
		authReq := string(op.AuthHints.RequiresAuth)
		signals := ""
		if len(op.Signals) > 0 {
			signals = "  signals=" + strings.Join(op.Signals, ",")
		}
		statuses := discoveryStatuses(op)
		statusText := ""
		if len(statuses) > 0 {
			statusText = "  status=" + strings.Join(statuses, ",")
		}
		fmt.Fprintf(w, "  %-8s  %-55s conf=%.2f  auth=%s%s%s\n",
			op.Protocol,
			op.Locator,
			op.Confidence,
			authReq,
			statusText,
			signals,
		)
	}

	if strings.TrimSpace(artifactPath) != "" {
		fmt.Fprintln(w, "\nArtifact")
		fmt.Fprintf(w, "  inventory: %s\n", artifactPath)
	}

	fmt.Fprintln(w, divider)
}

type discoveryMethodCount struct {
	Name  string
	Count int
}

func discoveryMethodCounts(operations []inventory.Operation) []discoveryMethodCount {
	counts := map[string]int{}
	for _, op := range operations {
		if op.REST == nil || strings.TrimSpace(op.REST.Method) == "" {
			continue
		}
		counts[strings.ToUpper(strings.TrimSpace(op.REST.Method))]++
	}
	methods := make([]discoveryMethodCount, 0, len(counts))
	for method, count := range counts {
		methods = append(methods, discoveryMethodCount{Name: method, Count: count})
	}
	sort.Slice(methods, func(i, j int) bool {
		if methods[i].Count == methods[j].Count {
			return methods[i].Name < methods[j].Name
		}
		return methods[i].Count > methods[j].Count
	})
	return methods
}

func discoveryStatuses(op inventory.Operation) []string {
	if op.REST == nil {
		return nil
	}
	seen := map[string]bool{}
	statuses := make([]string, 0, len(op.REST.ResponseMap))
	for _, response := range op.REST.ResponseMap {
		status := strings.TrimSpace(response.StatusCode)
		if status == "" || seen[status] {
			continue
		}
		seen[status] = true
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	return statuses
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}
