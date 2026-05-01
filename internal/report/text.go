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
const maxSummaryFindings = 25
const maxEnrichedCriticals = 5

const (
	findingSeverityWidth   = 10
	findingRuleWidth       = 14
	findingTitleWidth      = 46
	findingOperationWidth  = 22
	findingEndpointWidth   = 48
	discoveryProtocolWidth = 8
	discoveryLocatorWidth  = 44
	discoveryAuthWidth     = 11
	discoveryStatusWidth   = 16
	discoveryConfWidth     = 10
)

type Artifact struct {
	Kind string
	Path string
}

type FindingEnrichment struct {
	FindingID        string
	Summary          string
	Impact           string
	ExploitNarrative string
	FixSteps         []string
}

type SummaryOptions struct {
	RulesSkipped bool
	Artifacts    []Artifact
	Enrichments  []FindingEnrichment
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

	coverage := bundle.Coverage
	pct := 0.0
	if coverage.TotalOperations > 0 {
		pct = float64(coverage.Covered) / float64(coverage.TotalOperations) * 100
	}
	fmt.Fprintf(w, "Coverage  %d/%d operations seeded (%.0f%%)\n", coverage.Covered, coverage.TotalOperations, pct)

	byProto := map[string]map[string]string{}
	for _, entry := range coverage.Entries {
		key := entry.Target + "|" + entry.OperationID
		if byProto[entry.Protocol] == nil {
			byProto[entry.Protocol] = map[string]string{}
		}
		if entry.Status == "succeeded" || byProto[entry.Protocol][key] == "" {
			byProto[entry.Protocol][key] = entry.Status
		}
	}
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, proto := range protos {
		total := len(byProto[proto])
		covered := 0
		for _, status := range byProto[proto] {
			if status == "succeeded" {
				covered++
			}
		}
		fmt.Fprintf(w, "  %-9s %d/%d\n", proto+":", covered, total)
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
		summary := rules.Summarize(findings)
		severityCounts := findingSeverityCounts(summary)
		if len(severityCounts) > 0 {
			fmt.Fprintf(w, "  Severity  %s\n", strings.Join(severityCounts, "  "))
		}
		limit := len(findings)
		if limit > maxSummaryFindings {
			limit = maxSummaryFindings
		}
		sortedFindings := sortedFindingsForSummary(findings)
		fmt.Fprintln(w)
		printFindingsTableHeader(w)
		for _, f := range sortedFindings[:limit] {
			printFindingTableRow(w, f)
		}
		if omitted := len(findings) - limit; omitted > 0 {
			omittedCounts := findingSeverityCounts(rules.Summarize(sortedFindings[limit:]))
			omittedSummary := ""
			if len(omittedCounts) > 0 {
				omittedSummary = " (" + strings.Join(omittedCounts, "  ") + ")"
			}
			fmt.Fprintf(w, "  ... %d more findings omitted%s; see findings JSON or SARIF for full details\n", omitted, omittedSummary)
		}
	}

	if len(opts.Enrichments) > 0 {
		enrichByID := make(map[string]*FindingEnrichment, len(opts.Enrichments))
		for i := range opts.Enrichments {
			enrichByID[opts.Enrichments[i].FindingID] = &opts.Enrichments[i]
		}
		enrichedCriticals := 0
		for _, f := range sortedFindingsForSummary(findings) {
			if f.Severity != rules.SeverityCritical {
				continue
			}
			e, ok := enrichByID[f.ID]
			if !ok {
				continue
			}
			enrichedCriticals++
			if enrichedCriticals > maxEnrichedCriticals {
				break
			}
			fmt.Fprintf(w, "  %s %s\n", strings.ToUpper(string(f.Severity)), f.Title)
			fmt.Fprintf(w, "    %s\n", e.Summary)
			if e.Impact != "" {
				fmt.Fprintf(w, "    impact: %s\n", e.Impact)
			}
			if len(e.FixSteps) > 0 {
				fmt.Fprintf(w, "    fix: %s\n", e.FixSteps[0])
			}
			fmt.Fprintln(w)
		}
		remaining := len(opts.Enrichments) - enrichedCriticals
		if remaining > 0 {
			fmt.Fprintf(w, "  ... %d more enriched findings in findings.enriched.json\n\n", remaining)
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

func printFindingsTableHeader(w io.Writer) {
	fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %s\n",
		findingSeverityWidth, "SEVERITY",
		findingRuleWidth, "RULE",
		findingTitleWidth, "FINDING",
		findingOperationWidth, "OPERATION",
		"ENDPOINT",
	)
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 150))
}

func printFindingTableRow(w io.Writer, f rules.Finding) {
	titleLines := wrapCell(f.Title, findingTitleWidth)
	if len(titleLines) == 0 {
		titleLines = []string{"-"}
	}
	operationLines := wrapCell(firstNonEmpty(f.Locator, "-"), findingOperationWidth)
	if len(operationLines) == 0 {
		operationLines = []string{"-"}
	}
	endpointLines := wrapCell(findingEndpoint(f), findingEndpointWidth)
	if len(endpointLines) == 0 {
		endpointLines = []string{"-"}
	}
	lineCount := max(len(titleLines), len(operationLines), len(endpointLines))
	for i := 0; i < lineCount; i++ {
		severity := ""
		ruleID := ""
		title := cellLine(titleLines, i)
		operation := cellLine(operationLines, i)
		endpoint := cellLine(endpointLines, i)
		if i == 0 {
			severity = strings.ToUpper(string(f.Severity))
			ruleID = truncate(f.RuleID, findingRuleWidth)
		}
		fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %s\n",
			findingSeverityWidth, severity,
			findingRuleWidth, ruleID,
			findingTitleWidth, title,
			findingOperationWidth, operation,
			endpoint,
		)
	}
}

func findingEndpoint(f rules.Finding) string {
	if f.Evidence.Probe != nil {
		if url := strings.TrimSpace(f.Evidence.Probe.Request.URL); url != "" {
			return url
		}
		if method := strings.TrimSpace(f.Evidence.Probe.Request.GRPCMethod); method != "" {
			return method
		}
	}
	if url := strings.TrimSpace(f.Evidence.Seed.Request.URL); url != "" {
		return url
	}
	if method := strings.TrimSpace(f.Evidence.Seed.Request.GRPCMethod); method != "" {
		return method
	}
	return f.Locator
}

func findingSeverityCounts(summary rules.FindingSummary) []string {
	order := []string{
		string(rules.SeverityCritical),
		string(rules.SeverityHigh),
		string(rules.SeverityMedium),
		string(rules.SeverityLow),
		string(rules.SeverityInfo),
	}
	counts := make([]string, 0, len(order))
	for _, severity := range order {
		count := summary.BySeverity[severity]
		if count == 0 {
			continue
		}
		counts = append(counts, fmt.Sprintf("%s:%d", strings.ToUpper(severity), count))
	}
	return counts
}

func sortedFindingsForSummary(findings []rules.Finding) []rules.Finding {
	sorted := append([]rules.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := severityRank(sorted[i].Severity)
		right := severityRank(sorted[j].Severity)
		if left != right {
			return left < right
		}
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].Locator < sorted[j].Locator
	})
	return sorted
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func cellLine(lines []string, index int) string {
	if index < 0 || index >= len(lines) {
		return ""
	}
	return lines[index]
}

func max(values ...int) int {
	out := 0
	for _, value := range values {
		if value > out {
			out = value
		}
	}
	return out
}

func severityRank(severity rules.Severity) int {
	switch severity {
	case rules.SeverityCritical:
		return 0
	case rules.SeverityHigh:
		return 1
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 3
	case rules.SeverityInfo:
		return 4
	default:
		return 5
	}
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
		fmt.Fprintf(w, "  %-8s  %s\n", "METHOD", "COUNT")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 15))
		for _, method := range methods {
			fmt.Fprintf(w, "  %-8s  %d\n", method.Name, method.Count)
		}
	}

	fmt.Fprintln(w, "\nOperations")
	printDiscoveryOperationsTableHeader(w)
	for _, op := range inv.Operations {
		printDiscoveryOperationRow(w, op)
	}

	if strings.TrimSpace(artifactPath) != "" {
		fmt.Fprintln(w, "\nArtifact")
		fmt.Fprintf(w, "  inventory: %s\n", artifactPath)
	}

	fmt.Fprintln(w, divider)
}

func printDiscoveryOperationsTableHeader(w io.Writer) {
	fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
		discoveryProtocolWidth, "PROTOCOL",
		discoveryLocatorWidth, "OPERATION",
		discoveryAuthWidth, "AUTH",
		discoveryStatusWidth, "STATUS",
		discoveryConfWidth, "CONFIDENCE",
		"SIGNALS",
	)
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 113))
}

func printDiscoveryOperationRow(w io.Writer, op inventory.Operation) {
	statuses := discoveryStatuses(op)
	statusText := "-"
	if len(statuses) > 0 {
		statusText = strings.Join(statuses, ",")
	}
	signals := "-"
	if len(op.Signals) > 0 {
		signals = strings.Join(discoverySignals(op.Signals), ",")
	}
	locatorLines := wrapCell(op.Locator, discoveryLocatorWidth)
	if len(locatorLines) == 0 {
		locatorLines = []string{"-"}
	}
	for i, locator := range locatorLines {
		protocol := ""
		authReq := ""
		status := ""
		conf := ""
		rowSignals := ""
		if i == 0 {
			protocol = string(op.Protocol)
			authReq = discoveryAuthRequirement(op.AuthHints.RequiresAuth)
			status = statusText
			conf = fmt.Sprintf("%.2f", op.Confidence)
			rowSignals = signals
		}
		fmt.Fprintf(w, "  %-*s  %-*s  %-*s  %-*s  %-*s  %s\n",
			discoveryProtocolWidth, protocol,
			discoveryLocatorWidth, locator,
			discoveryAuthWidth, authReq,
			discoveryStatusWidth, status,
			discoveryConfWidth, conf,
			rowSignals,
		)
	}
}

func discoveryAuthRequirement(requirement inventory.AuthRequirement) string {
	switch requirement {
	case inventory.AuthRequirementYes:
		return "required"
	case inventory.AuthRequirementNo:
		return "none"
	default:
		return "unspecified"
	}
}

func discoverySignals(signals []string) []string {
	out := make([]string, 0, len(signals))
	for _, signal := range signals {
		switch signal {
		case "specified_but_unseen":
			out = append(out, "in_spec_not_seen_runtime")
		case "observed_but_undocumented":
			out = append(out, "observed_not_in_spec")
		default:
			out = append(out, signal)
		}
	}
	return out
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

func wrapCell(s string, width int) []string {
	words := strings.Fields(strings.TrimSpace(s))
	if len(words) == 0 || width <= 0 {
		return nil
	}
	lines := []string{}
	current := ""
	for _, word := range words {
		for runeLen(word) > width {
			if current != "" {
				lines = append(lines, current)
				current = ""
			}
			head, tail := splitRunes(word, width)
			lines = append(lines, head)
			word = tail
		}
		if current == "" {
			current = word
			continue
		}
		if runeLen(current)+1+runeLen(word) <= width {
			current += " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

func splitRunes(s string, n int) (string, string) {
	runes := []rune(s)
	if n >= len(runes) {
		return s, ""
	}
	return string(runes[:n]), string(runes[n:])
}

func runeLen(s string) int {
	return len([]rune(s))
}
