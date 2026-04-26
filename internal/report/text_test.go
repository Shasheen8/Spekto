package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/Shasheen8/Spekto/internal/rules"
)

func TestPrintSummaryCapsFindingsForCILogs(t *testing.T) {
	findings := make([]rules.Finding, 30)
	for i := range findings {
		severity := rules.SeverityHigh
		if i >= maxSummaryFindings {
			severity = rules.SeverityCritical
		}
		findings[i] = rules.Finding{
			RuleID:   fmt.Sprintf("RULE%03d", i+1),
			Severity: severity,
			Title:    "test finding",
			Locator:  fmt.Sprintf("GET:/v1/%d", i+1),
		}
	}

	var buf bytes.Buffer
	PrintSummary(&buf, executor.Bundle{
		Summary: executor.BundleSummary{
			Total:     1,
			Succeeded: 1,
			ByProtocol: map[string]int{
				string(inventory.ProtocolREST): 1,
			},
		},
	}, findings)

	output := buf.String()
	if !strings.Contains(output, "Findings  30 total") {
		t.Fatalf("expected total finding count, got:\n%s", output)
	}
	if !strings.Contains(output, "SEVERITY") || !strings.Contains(output, "FINDING") || !strings.Contains(output, "OPERATION") {
		t.Fatalf("expected findings table header, got:\n%s", output)
	}
	if strings.Count(output, "RULE0") != maxSummaryFindings {
		t.Fatalf("expected %d printed findings, got:\n%s", maxSummaryFindings, output)
	}
	if !strings.Contains(output, "RULE026") {
		t.Fatalf("expected critical findings to be shown before lower severity findings, got:\n%s", output)
	}
	if !strings.Contains(output, "5 more findings omitted") || !strings.Contains(output, "HIGH:5") {
		t.Fatalf("expected omitted findings hint with severity counts, got:\n%s", output)
	}
}

func TestPrintSummaryWrapsLongFindingTitles(t *testing.T) {
	probeEvidence := executor.Evidence{
		Request: executor.RequestEvidence{
			URL: "http://127.0.0.1:5002/users/v1/name1?admin=true",
		},
	}
	findings := []rules.Finding{{
		RuleID:   "HDR005",
		Severity: rules.SeverityHigh,
		Title:    "IP-based authentication bypass via X-Forwarded-For accepted by target",
		Locator:  "GET:/",
		Evidence: rules.FindingEvidence{
			Seed: executor.Evidence{
				Request: executor.RequestEvidence{
					URL: "http://127.0.0.1:5002/users/v1/name1",
				},
			},
			Probe: &probeEvidence,
		},
	}}

	var buf bytes.Buffer
	PrintSummary(&buf, executor.Bundle{
		Summary: executor.BundleSummary{
			Total:     1,
			Succeeded: 1,
			ByProtocol: map[string]int{
				string(inventory.ProtocolREST): 1,
			},
		},
	}, findings)

	output := buf.String()
	if !strings.Contains(output, "IP-based authentication bypass via") ||
		!strings.Contains(output, "X-Forwarded-For accepted by target") ||
		!strings.Contains(output, "accepted by target") {
		t.Fatalf("expected long finding title to wrap without truncation, got:\n%s", output)
	}
	if !strings.Contains(output, "ENDPOINT") ||
		!strings.Contains(output, "http://127.0.0.1:5002/users/v1/name1?admin=true") {
		t.Fatalf("expected finding endpoint column to use probe URL, got:\n%s", output)
	}
}

func TestPrintSummaryReportsOmittedCriticalFindings(t *testing.T) {
	findings := make([]rules.Finding, 30)
	for i := range findings {
		findings[i] = rules.Finding{
			RuleID:   fmt.Sprintf("CRIT%03d", i+1),
			Severity: rules.SeverityCritical,
			Title:    "critical test finding",
			Locator:  fmt.Sprintf("GET:/critical/%d", i+1),
		}
	}

	var buf bytes.Buffer
	PrintSummary(&buf, executor.Bundle{
		Summary: executor.BundleSummary{
			Total:     1,
			Succeeded: 1,
			ByProtocol: map[string]int{
				string(inventory.ProtocolREST): 1,
			},
		},
	}, findings)

	output := buf.String()
	if !strings.Contains(output, "5 more findings omitted (CRITICAL:5)") {
		t.Fatalf("expected omitted critical count, got:\n%s", output)
	}
}

func TestPrintDiscoverySummaryUsesOperationsTable(t *testing.T) {
	op := inventory.NewRESTOperation("GET", "/users/v1/{username}")
	op.Confidence = 0.9
	op.AuthHints.RequiresAuth = inventory.AuthRequirementUnknown
	op.Provenance.Specified = true
	op.REST = &inventory.RESTDetails{
		Method:         "GET",
		NormalizedPath: "/users/v1/{username}",
		ResponseMap: []inventory.ResponseMeta{{
			StatusCode: "200",
		}},
	}
	inv := inventory.Merge([]inventory.Operation{op})

	var buf bytes.Buffer
	PrintDiscoverySummary(&buf, inv, "inventory.json")

	output := buf.String()
	for _, want := range []string{"PROTOCOL", "OPERATION", "AUTH", "STATUS", "CONFIDENCE", "SIGNALS", "unspecified", "in_spec_not_seen_runtime", "GET:/users/v1/{username}"} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected discovery table output to contain %q, got:\n%s", want, output)
		}
	}
}
