package report

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/Shasheen8/Spekto/internal/rules"
)

func TestSARIFIncludesPartialFingerprints(t *testing.T) {
	data, err := SARIF([]rules.Finding{{
		ID:          "AUTH001-deadbeef",
		RuleID:      "AUTH001",
		Severity:    rules.SeverityHigh,
		Title:       "Authentication bypass",
		Description: "bypass",
		Target:      "prod",
		Protocol:    inventory.ProtocolREST,
		OperationID: "op-1",
		Locator:     "GET:/v1/private",
		FoundAt:     time.Now(),
		Evidence: rules.FindingEvidence{Seed: executor.Evidence{Request: executor.RequestEvidence{
			URL: "https://api.example.com/v1/private",
		}}},
	}})
	if err != nil {
		t.Fatalf("SARIF returned error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	got := log.Runs[0].Results[0].PartialFingerprints["spektoFindingId"]
	if got != "AUTH001-deadbeef" {
		t.Fatalf("unexpected fingerprint: %s", got)
	}
}
