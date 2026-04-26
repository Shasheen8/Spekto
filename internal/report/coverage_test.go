package report

import (
	"testing"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestBuildCoverageSummaryUsesUniqueOperationCoverage(t *testing.T) {
	bundle := executor.Bundle{Results: []executor.Result{
		{
			Protocol:        inventory.ProtocolREST,
			Target:          "rest-api",
			OperationID:     "op-1",
			Locator:         "GET:/v1/users",
			AuthContextName: "owner",
			Status:          "succeeded",
		},
		{
			Protocol:        inventory.ProtocolREST,
			Target:          "rest-api",
			OperationID:     "op-1",
			Locator:         "GET:/v1/users",
			AuthContextName: "viewer",
			Status:          "failed",
			Error:           "403 forbidden",
			Evidence: executor.Evidence{
				Response: executor.ResponseEvidence{StatusCode: 403},
			},
		},
	}}
	bundle.Finalize()

	summary := BuildCoverageSummary(bundle)

	if summary.TotalOperations != 1 || summary.Succeeded != 1 || summary.Failed != 0 {
		t.Fatalf("expected one covered operation, got %#v", summary)
	}
	if summary.ExecutionAttempts != 2 {
		t.Fatalf("expected two execution attempts, got %#v", summary)
	}
	if summary.CoveragePct != 100 {
		t.Fatalf("expected 100%% operation coverage, got %f", summary.CoveragePct)
	}
	if summary.ByProtocol["rest"].Total != 1 || summary.ByProtocol["rest"].Succeeded != 1 {
		t.Fatalf("expected unique protocol coverage, got %#v", summary.ByProtocol)
	}
}
