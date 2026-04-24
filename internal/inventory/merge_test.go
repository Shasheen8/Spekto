package inventory

import "testing"

func TestMergeDedupesByIDAndCombinesMetadata(t *testing.T) {
	a := NewRESTOperation("GET", "/v1/models/{id}")
	a.Origins = []string{"https://api.example.com"}
	a.SourceRefs = []SourceRef{{
		Type:         SourceSpec,
		Location:     "openapi.yaml",
		ParserFamily: "openapi_3_1",
		SupportLevel: SupportLevelFull,
	}}
	a.Provenance = Provenance{Specified: true}
	a.Confidence = 0.9
	a.Tags = []string{"models"}
	a.AuthHints = AuthHints{
		RequiresAuth: AuthRequirementYes,
		AuthSchemes:  []AuthScheme{AuthSchemeBearer},
	}

	b := NewRESTOperation("GET", "/v1/models/{id}")
	b.Origins = []string{"https://api-backup.example.com"}
	b.SourceRefs = []SourceRef{{
		Type:         SourceTraffic,
		Location:     "traffic.har",
		ParserFamily: "har",
		SupportLevel: SupportLevelFull,
	}}
	b.Provenance = Provenance{Observed: true}
	b.Confidence = 0.8
	b.Tags = []string{"observed"}
	b.AuthHints = AuthHints{
		RequiresAuth: AuthRequirementUnknown,
		AuthSchemes:  []AuthScheme{AuthSchemeBearer},
	}

	merged := Merge([]Operation{a}, []Operation{b})
	if len(merged.Operations) != 1 {
		t.Fatalf("expected 1 merged operation, got %d", len(merged.Operations))
	}
	op := merged.Operations[0]
	if len(op.Origins) != 2 {
		t.Fatalf("expected merged origins, got %#v", op.Origins)
	}
	if len(op.SourceRefs) != 2 {
		t.Fatalf("expected merged source refs, got %#v", op.SourceRefs)
	}
	if !op.Provenance.Specified || !op.Provenance.Observed {
		t.Fatalf("expected merged provenance, got %#v", op.Provenance)
	}
	if len(op.Signals) != 0 {
		t.Fatalf("expected no unresolved provenance signals, got %#v", op.Signals)
	}
	if op.Confidence <= 0.9 {
		t.Fatalf("expected confidence boost after merge, got %f", op.Confidence)
	}
	if len(op.Tags) != 2 {
		t.Fatalf("expected merged tags, got %#v", op.Tags)
	}
	if op.AuthHints.RequiresAuth != AuthRequirementYes {
		t.Fatalf("expected auth requirement to remain yes, got %s", op.AuthHints.RequiresAuth)
	}
	if merged.Summary.Total != 1 || merged.Summary.ByProtocol["rest"] != 1 {
		t.Fatalf("unexpected summary: %#v", merged.Summary)
	}
}

func TestMergeMarksSpecifiedButUnseenAndObservedUndocumented(t *testing.T) {
	specified := NewRESTOperation("GET", "/v1/spec-only")
	specified.Provenance = Provenance{Specified: true}

	observed := NewRESTOperation("POST", "/v1/traffic-only")
	observed.Provenance = Provenance{Observed: true}

	merged := Merge([]Operation{specified, observed})
	if len(merged.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(merged.Operations))
	}

	var specSignals []string
	var observedSignals []string
	for _, op := range merged.Operations {
		switch op.Locator {
		case "GET:/v1/spec-only":
			specSignals = op.Signals
		case "POST:/v1/traffic-only":
			observedSignals = op.Signals
		}
	}
	if len(specSignals) != 1 || specSignals[0] != "specified_but_unseen" {
		t.Fatalf("unexpected spec signals: %#v", specSignals)
	}
	if len(observedSignals) != 1 || observedSignals[0] != "observed_but_undocumented" {
		t.Fatalf("unexpected observed signals: %#v", observedSignals)
	}
	if merged.Summary.SpecifiedButUnseenCount != 1 || merged.Summary.ObservedUndocumentedCount != 1 {
		t.Fatalf("unexpected summary counts: %#v", merged.Summary)
	}
}

func TestMergeAuthRequirementCannotBeDowngradedByOrder(t *testing.T) {
	unauthenticated := NewRESTOperation("GET", "/v1/private")
	unauthenticated.AuthHints = AuthHints{RequiresAuth: AuthRequirementNo}

	authenticated := NewRESTOperation("GET", "/v1/private")
	authenticated.AuthHints = AuthHints{RequiresAuth: AuthRequirementYes}

	merged := Merge([]Operation{unauthenticated}, []Operation{authenticated})
	if got := merged.Operations[0].AuthHints.RequiresAuth; got != AuthRequirementYes {
		t.Fatalf("expected auth requirement yes to win, got %s", got)
	}

	merged = Merge([]Operation{authenticated}, []Operation{unauthenticated})
	if got := merged.Operations[0].AuthHints.RequiresAuth; got != AuthRequirementYes {
		t.Fatalf("expected auth requirement yes to win regardless of order, got %s", got)
	}
}
