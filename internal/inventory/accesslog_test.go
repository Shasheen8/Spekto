package inventory

import "testing"

func TestParseAccessLogBuildsObservedOperations(t *testing.T) {
	data := []byte(`{"method":"GET","url":"https://api.example.com/v1/models","status":200}
{"method":"POST","host":"api.example.com","path":"/v1/models","status":201}`)

	doc, err := ParseAccessLog(data, "access.log.jsonl")
	if err != nil {
		t.Fatalf("ParseAccessLog returned error: %v", err)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}
	for _, op := range doc.Operations {
		if !op.Provenance.Observed {
			t.Fatalf("expected observed provenance")
		}
	}
}

func TestParseAccessLogDedupesRepeatedOperations(t *testing.T) {
	data := []byte(`[
	  {"method":"GET","url":"https://api.example.com/v1/models","status":200},
	  {"method":"GET","url":"https://api.example.com/v1/models","status":200}
	]`)

	doc, err := ParseAccessLog(data, "access.json")
	if err != nil {
		t.Fatalf("ParseAccessLog returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(doc.Operations))
	}
}

func TestParseAccessLogNormalizesNumericSegments(t *testing.T) {
	data := []byte(`[
	  {"method":"GET","url":"https://api.example.com/v1/orders/1001","status":200},
	  {"method":"GET","url":"https://api.example.com/v1/orders/1002","status":200}
	]`)

	doc, err := ParseAccessLog(data, "access.json")
	if err != nil {
		t.Fatalf("ParseAccessLog returned error: %v", err)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation after cross-ID normalization, got %d", len(doc.Operations))
	}
	op := doc.Operations[0]
	if op.REST == nil || op.REST.NormalizedPath != "/v1/orders/{id}" {
		t.Fatalf("expected normalized path /v1/orders/{id}, got %#v", op.REST)
	}
	// Both original IDs should be preserved as examples.
	var pathExamples []string
	for _, ex := range op.Examples.Parameters {
		if ex.In == "path" {
			pathExamples = append(pathExamples, ex.Example)
		}
	}
	if len(pathExamples) < 2 {
		t.Fatalf("expected both ID examples preserved, got %v", pathExamples)
	}
}
