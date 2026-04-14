package inventory

import "testing"

func TestParseHARBuildsObservedOperations(t *testing.T) {
	data := []byte(`{
	  "log": {
	    "entries": [
	      {
	        "request": {
	          "method": "GET",
	          "url": "https://api.example.com/v1/models?id=model_1",
	          "headers": [{"name":"Authorization","value":"Bearer token"}],
	          "queryString": [{"name":"id","value":"model_1"}],
	          "cookies": []
	        },
	        "response": {
	          "status": 200,
	          "content": {"mimeType":"application/json"}
	        }
	      },
	      {
	        "request": {
	          "method": "POST",
	          "url": "https://api.example.com/v1/models",
	          "headers": [{"name":"Content-Type","value":"application/json"}],
	          "queryString": [],
	          "cookies": [{"name":"session","value":"abc"}],
	          "postData": {
	            "mimeType":"application/json",
	            "text":"{\"name\":\"gpt-test\"}"
	          }
	        },
	        "response": {
	          "status": 201,
	          "content": {"mimeType":"application/json"}
	        }
	      }
	    ]
	  }
	}`)

	doc, err := ParseHAR(data, "traffic.har")
	if err != nil {
		t.Fatalf("ParseHAR returned error: %v", err)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}

	getOp := doc.Operations[0]
	postOp := doc.Operations[1]
	if !getOp.Provenance.Observed || !postOp.Provenance.Observed {
		t.Fatalf("expected observed provenance on all operations")
	}
	if getOp.REST == nil || getOp.REST.NormalizedPath != "/v1/models" {
		t.Fatalf("unexpected GET path: %#v", getOp.REST)
	}
	if len(getOp.REST.QueryParams) != 1 || getOp.REST.QueryParams[0].Name != "id" {
		t.Fatalf("unexpected query params: %#v", getOp.REST.QueryParams)
	}
	if postOp.REST == nil || postOp.REST.RequestBody == nil {
		t.Fatalf("expected request body metadata on POST operation")
	}
	if len(postOp.Examples.RequestBodies) != 1 {
		t.Fatalf("expected one request body example, got %#v", postOp.Examples.RequestBodies)
	}
	if postOp.Targets[0] != "https://api.example.com" {
		t.Fatalf("unexpected target origin: %#v", postOp.Targets)
	}
}

func TestParseHARDeDupesRepeatedRequests(t *testing.T) {
	data := []byte(`{
	  "log": {
	    "entries": [
	      {
	        "request": {
	          "method": "GET",
	          "url": "https://api.example.com/v1/models/1",
	          "headers": [],
	          "queryString": []
	        },
	        "response": {
	          "status": 200,
	          "content": {"mimeType":"application/json"}
	        }
	      },
	      {
	        "request": {
	          "method": "GET",
	          "url": "https://api.example.com/v1/models/1",
	          "headers": [{"name":"X-Trace","value":"abc"}],
	          "queryString": []
	        },
	        "response": {
	          "status": 200,
	          "content": {"mimeType":"application/json"}
	        }
	      }
	    ]
	  }
	}`)

	doc, err := ParseHAR(data, "traffic.har")
	if err != nil {
		t.Fatalf("ParseHAR returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation after HAR dedupe, got %d", len(doc.Operations))
	}
	op := doc.Operations[0]
	// Numeric segment must have been normalized.
	if op.REST == nil || op.REST.NormalizedPath != "/v1/models/{id}" {
		t.Fatalf("expected normalized path /v1/models/{id}, got %#v", op.REST)
	}
	if len(op.REST.PathParams) != 1 || op.REST.PathParams[0].Name != "id" {
		t.Fatalf("expected path param {id}, got %#v", op.REST.PathParams)
	}
	if len(op.REST.HeaderParams) != 1 {
		t.Fatalf("expected merged header examples, got %#v", op.REST.HeaderParams)
	}
}

func TestParseHARCollapsesDifferentIDsToOneOperation(t *testing.T) {
	// The key benefit of path normalization: /v1/models/42 and /v1/models/87
	// are the same operation. They must produce one inventory record, not two.
	data := []byte(`{
	  "log": {
	    "entries": [
	      {
	        "request": {
	          "method": "GET",
	          "url": "https://api.example.com/v1/models/42",
	          "headers": [],
	          "queryString": []
	        },
	        "response": {"status": 200, "content": {"mimeType":"application/json"}}
	      },
	      {
	        "request": {
	          "method": "GET",
	          "url": "https://api.example.com/v1/models/87",
	          "headers": [],
	          "queryString": []
	        },
	        "response": {"status": 200, "content": {"mimeType":"application/json"}}
	      }
	    ]
	  }
	}`)

	doc, err := ParseHAR(data, "traffic.har")
	if err != nil {
		t.Fatalf("ParseHAR returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation after cross-ID normalization, got %d: %v",
			len(doc.Operations), operationLocators(doc.Operations))
	}
	op := doc.Operations[0]
	if op.REST == nil || op.REST.NormalizedPath != "/v1/models/{id}" {
		t.Fatalf("expected normalized path, got %#v", op.REST)
	}
	// Both original values must be preserved as examples for seed generation.
	paramExamples := pathParamExamples(op.Examples.Parameters)
	if len(paramExamples) < 2 {
		t.Fatalf("expected both ID examples to be preserved, got %v", paramExamples)
	}
}

func TestParseHARNormalizesUUIDSegments(t *testing.T) {
	data := []byte(`{
	  "log": {
	    "entries": [
	      {
	        "request": {
	          "method": "DELETE",
	          "url": "https://api.example.com/v1/users/550e8400-e29b-41d4-a716-446655440000",
	          "headers": [],
	          "queryString": []
	        },
	        "response": {"status": 204, "content": {"mimeType":""}}
	      }
	    ]
	  }
	}`)

	doc, err := ParseHAR(data, "traffic.har")
	if err != nil {
		t.Fatalf("ParseHAR returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(doc.Operations))
	}
	op := doc.Operations[0]
	if op.REST == nil || op.REST.NormalizedPath != "/v1/users/{id}" {
		t.Fatalf("expected UUID segment normalized, got %v", op.REST)
	}
	if op.REST.PathParams[0].Type != "string" {
		t.Fatalf("expected UUID param type string, got %q", op.REST.PathParams[0].Type)
	}
}

func operationLocators(ops []Operation) []string {
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = op.Locator
	}
	return out
}

func pathParamExamples(params []ParameterValue) []ParameterValue {
	var out []ParameterValue
	for _, p := range params {
		if p.In == "path" {
			out = append(out, p)
		}
	}
	return out
}
