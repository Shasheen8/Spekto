package inventory

import "testing"

func TestParseInventoryRecomputesSummary(t *testing.T) {
	data := []byte(`{
	  "operations": [
	    {
	      "id": "op-rest",
	      "protocol": "rest",
	      "family": "http",
	      "locator": "GET:/v1/models",
	      "display_name": "GET:/v1/models",
	      "provenance": {"specified": true},
	      "confidence": 0.9,
	      "auth_hints": {"requires_auth": "unknown"},
	      "schema_refs": {"responses": {}},
	      "status": "normalized"
	    },
	    {
	      "id": "op-graphql",
	      "protocol": "graphql",
	      "family": "graphql",
	      "locator": "query:model",
	      "display_name": "query:model",
	      "provenance": {"observed": true},
	      "confidence": 0.8,
	      "auth_hints": {"requires_auth": "unknown"},
	      "schema_refs": {"responses": {}},
	      "status": "normalized"
	    }
	  ],
	  "summary": {
	    "total": 999
	  }
	}`)

	inv, err := ParseInventory(data)
	if err != nil {
		t.Fatalf("ParseInventory returned error: %v", err)
	}
	if inv.Summary.Total != 2 {
		t.Fatalf("expected total 2, got %d", inv.Summary.Total)
	}
	if inv.Summary.ByProtocol["rest"] != 1 {
		t.Fatalf("expected one rest operation, got %d", inv.Summary.ByProtocol["rest"])
	}
	if inv.Summary.ByProtocol["graphql"] != 1 {
		t.Fatalf("expected one graphql operation, got %d", inv.Summary.ByProtocol["graphql"])
	}
	if inv.Summary.SpecifiedCount != 1 || inv.Summary.ObservedCount != 1 {
		t.Fatalf("unexpected summary counts: %#v", inv.Summary)
	}
}
