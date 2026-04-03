package inventory

import "testing"

func TestStableOperationIDDeterministic(t *testing.T) {
	first := StableOperationID(ProtocolREST, "GET:/v1/models/{model_id}")
	second := StableOperationID(ProtocolREST, "GET:/v1/models/{model_id}")
	if first != second {
		t.Fatalf("expected deterministic IDs, got %q and %q", first, second)
	}
}

func TestNewRESTOperationNormalizesPath(t *testing.T) {
	op := NewRESTOperation("get", "v1/models//{id}")
	if op.REST != nil {
		t.Fatalf("expected base operation without rest details attached")
	}
	if op.Locator != "GET:/v1/models/{id}" {
		t.Fatalf("unexpected locator: %s", op.Locator)
	}
	if op.Protocol != ProtocolREST {
		t.Fatalf("unexpected protocol: %s", op.Protocol)
	}
	if op.Family != FamilyHTTP {
		t.Fatalf("unexpected family: %s", op.Family)
	}
}
