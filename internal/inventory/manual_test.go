package inventory

import "testing"

func TestParseManualBuildsMixedOperations(t *testing.T) {
	data := []byte(`
rest:
  - method: GET
    path: /v1/models
    target: https://api.example.com
    requires_auth: true
    auth_schemes: [bearer]
graphql:
  - root_kind: query
    name: model
    arguments: [id:ID!]
grpc:
  - package: spekto.v1
    service: ModelService
    rpc: GetModel
    request_message: spekto.v1.GetModelRequest
    response_message: spekto.v1.Model
`)

	doc, err := ParseManual(data, "manual.yaml")
	if err != nil {
		t.Fatalf("ParseManual returned error: %v", err)
	}
	if len(doc.Operations) != 3 {
		t.Fatalf("expected 3 operations, got %d", len(doc.Operations))
	}
	for _, op := range doc.Operations {
		if !op.Provenance.ManuallySeeded {
			t.Fatalf("expected manual provenance: %#v", op.Provenance)
		}
		if len(op.SourceRefs) != 1 || op.SourceRefs[0].Type != SourceManual {
			t.Fatalf("unexpected source refs: %#v", op.SourceRefs)
		}
	}
}

func TestParseManualAcceptsRootArray(t *testing.T) {
	data := []byte(`[
	  {"protocol":"rest","method":"POST","path":"/v1/models"},
	  {"protocol":"graphql","root_kind":"mutation","name":"createModel"}
	]`)

	doc, err := ParseManual(data, "manual.json")
	if err != nil {
		t.Fatalf("ParseManual returned error: %v", err)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}
}
