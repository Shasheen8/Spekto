package inventory

import "testing"

func TestParsePostmanBuildsObservedOperations(t *testing.T) {
	data := []byte(`{
	  "item": [
	    {
	      "name": "List models",
	      "request": {
	        "method": "GET",
	        "header": [{"key":"Authorization","value":"Bearer token"}],
	        "url": {
	          "raw": "https://api.example.com/v1/models?limit=10",
	          "query": [{"key":"limit","value":"10"}]
	        }
	      }
	    },
	    {
	      "name": "Create model",
	      "request": {
	        "method": "POST",
	        "url": {
	          "host": ["api","example","com"],
	          "path": ["v1","models"]
	        },
	        "body": {
	          "mode": "raw",
	          "raw": "{\"name\":\"gpt-test\"}"
	        }
	      }
	    }
	  ]
	}`)

	doc, err := ParsePostman(data, "collection.json")
	if err != nil {
		t.Fatalf("ParsePostman returned error: %v", err)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}
	getOp := doc.Operations[0]
	postOp := doc.Operations[1]
	if !getOp.Provenance.Observed || !postOp.Provenance.Observed {
		t.Fatalf("expected observed provenance")
	}
	if getOp.DisplayName != "List models" {
		t.Fatalf("unexpected display name: %s", getOp.DisplayName)
	}
	if getOp.REST == nil || len(getOp.REST.QueryParams) != 1 {
		t.Fatalf("expected query params on GET operation")
	}
	if postOp.REST == nil || postOp.REST.RequestBody == nil {
		t.Fatalf("expected request body metadata on POST operation")
	}
	if postOp.Targets[0] != "https://api.example.com" {
		t.Fatalf("unexpected target: %#v", postOp.Targets)
	}
}

func TestParsePostmanNestedItems(t *testing.T) {
	data := []byte(`{
	  "item": [
	    {
	      "name": "Folder",
	      "item": [
	        {
	          "name": "Get model",
	          "request": {
	            "method": "GET",
	            "url": {"raw":"https://api.example.com/v1/models/1"}
	          }
	        }
	      ]
	    }
	  ]
	}`)

	doc, err := ParsePostman(data, "collection.json")
	if err != nil {
		t.Fatalf("ParsePostman returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(doc.Operations))
	}
	op := doc.Operations[0]
	if op.DisplayName != "Get model" {
		t.Fatalf("unexpected display name: %s", op.DisplayName)
	}
	// Numeric segment must be normalized.
	if op.REST == nil || op.REST.NormalizedPath != "/v1/models/{id}" {
		t.Fatalf("expected normalized path /v1/models/{id}, got %#v", op.REST)
	}
	if len(op.Examples.Parameters) == 0 || op.Examples.Parameters[0].Example != "1" {
		t.Fatalf("expected original value '1' as path param example, got %v", op.Examples.Parameters)
	}
}

func TestParsePostmanCollapsesDifferentIDsToOneOperation(t *testing.T) {
	data := []byte(`{
	  "item": [
	    {
	      "name": "Get user A",
	      "request": {
	        "method": "GET",
	        "url": {"raw":"https://api.example.com/v1/users/100"}
	      }
	    },
	    {
	      "name": "Get user B",
	      "request": {
	        "method": "GET",
	        "url": {"raw":"https://api.example.com/v1/users/200"}
	      }
	    }
	  ]
	}`)

	doc, err := ParsePostman(data, "collection.json")
	if err != nil {
		t.Fatalf("ParsePostman returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation after cross-ID normalization, got %d", len(doc.Operations))
	}
	if doc.Operations[0].REST == nil || doc.Operations[0].REST.NormalizedPath != "/v1/users/{id}" {
		t.Fatalf("expected normalized path, got %#v", doc.Operations[0].REST)
	}
}
