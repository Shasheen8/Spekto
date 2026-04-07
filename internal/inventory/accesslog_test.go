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
