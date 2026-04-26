package rules

import (
	"strings"
	"testing"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestSelectRulesGatesUnsafeAndLiveSSRFByDefault(t *testing.T) {
	selected := SelectRules(DefaultRules(), nil, nil, RuleSafety{})
	ids := selectedRuleIDs(selected)

	for _, id := range []string{"HDR004", "SEC002", "SEC004", "INJ006"} {
		if ids[id] {
			t.Fatalf("rule %s should be gated by default", id)
		}
	}
}

func TestSelectRulesCanOptIntoUnsafeAndLiveSSRF(t *testing.T) {
	selected := SelectRules(DefaultRules(), nil, nil, RuleSafety{
		AllowUnsafeRules: true,
		AllowLiveSSRF:    true,
	})
	ids := selectedRuleIDs(selected)

	for _, id := range []string{"HDR004", "SEC002", "SEC004", "INJ006"} {
		if !ids[id] {
			t.Fatalf("rule %s should be selected when explicitly enabled", id)
		}
	}
}

func TestSelectRulesIncludesXSSRulesInSafeDefaults(t *testing.T) {
	selected := SelectRules(DefaultRules(), nil, nil, RuleSafety{})
	ids := selectedRuleIDs(selected)

	for _, id := range []string{"XSS001", "XSS002"} {
		if !ids[id] {
			t.Fatalf("rule %s should be selected by default", id)
		}
	}
}

func TestPathInjectedURLDoesNotDoubleEscapePayload(t *testing.T) {
	got := pathInjectedURL("GET:/v1/models/{id}", "https://api.example.com/v1/models/abc", `' OR '1'='1`)
	if strings.Contains(got, "%25") {
		t.Fatalf("payload was double escaped: %s", got)
	}
	if got != "https://api.example.com/v1/models/%27%20OR%20%271%27=%271" {
		t.Fatalf("unexpected injected URL: %s", got)
	}
}

func TestFindingIDsIncludeProbeVariant(t *testing.T) {
	seed := executor.Result{
		Protocol:        inventory.ProtocolREST,
		Target:          "prod",
		OperationID:     "op-1",
		Locator:         "GET:/v1/models/{id}",
		AuthContextName: "user",
	}
	pathFinding := newFinding("INJ002", SeverityHigh, ConfidenceMedium, "SQL", "path", seed, FindingEvidence{
		Seed: seed.Evidence,
		Probe: &executor.Evidence{Request: executor.RequestEvidence{
			Method: "GET",
			URL:    "https://api.example.com/v1/models/%27",
		}},
	}, "", 0, "")
	queryFinding := newFinding("INJ002", SeverityHigh, ConfidenceMedium, "SQL", "query", seed, FindingEvidence{
		Seed: seed.Evidence,
		Probe: &executor.Evidence{Request: executor.RequestEvidence{
			Method: "GET",
			URL:    "https://api.example.com/v1/models/abc?id=%27",
		}},
	}, "", 0, "")

	if pathFinding.ID == queryFinding.ID {
		t.Fatalf("expected distinct finding IDs for distinct probe variants")
	}
}

func selectedRuleIDs(rules []Rule) map[string]bool {
	out := make(map[string]bool, len(rules))
	for _, rule := range rules {
		out[rule.ID()] = true
	}
	return out
}
