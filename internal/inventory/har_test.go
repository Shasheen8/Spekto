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
	if len(doc.Operations[0].REST.HeaderParams) != 1 {
		t.Fatalf("expected merged header examples, got %#v", doc.Operations[0].REST.HeaderParams)
	}
}
