package inventory

import (
	"testing"
)

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

func TestNormalizeTrafficPath(t *testing.T) {
	cases := []struct {
		input        string
		wantPath     string
		wantParamLen int
		wantExample  string // first example value, if any
	}{
		{"/v1/users/42", "/v1/users/{id}", 1, "42"},
		{"/v1/users/550e8400-e29b-41d4-a716-446655440000", "/v1/users/{id}", 1, "550e8400-e29b-41d4-a716-446655440000"},
		{"/v1/users/42/posts/99", "/v1/users/{id}/posts/{id2}", 2, "42"},
		{"/v1/models", "/v1/models", 0, ""},
		{"/v1/models/meta-llama", "/v1/models/meta-llama", 0, ""},
		{"/", "/", 0, ""},
		{"v1/items/7", "/v1/items/{id}", 1, "7"},
	}
	for _, tc := range cases {
		norm, params, examples := NormalizeTrafficPath(tc.input)
		if norm != tc.wantPath {
			t.Errorf("NormalizeTrafficPath(%q) path = %q, want %q", tc.input, norm, tc.wantPath)
		}
		if len(params) != tc.wantParamLen {
			t.Errorf("NormalizeTrafficPath(%q) params len = %d, want %d", tc.input, len(params), tc.wantParamLen)
		}
		if tc.wantExample != "" {
			if len(examples) == 0 || examples[0].Example != tc.wantExample {
				t.Errorf("NormalizeTrafficPath(%q) first example = %v, want %q", tc.input, examples, tc.wantExample)
			}
		}
	}
}

func TestNormalizeTrafficPathDeduplicatesViaOperationID(t *testing.T) {
	// Two HAR entries with different numeric IDs should produce the same operation ID
	// once paths are normalized.
	norm1, _, _ := NormalizeTrafficPath("/v1/users/42")
	norm2, _, _ := NormalizeTrafficPath("/v1/users/99")
	if norm1 != norm2 {
		t.Fatalf("expected same normalized path, got %q and %q", norm1, norm2)
	}
	id1 := StableOperationID(ProtocolREST, "GET:"+norm1)
	id2 := StableOperationID(ProtocolREST, "GET:"+norm2)
	if id1 != id2 {
		t.Fatalf("expected same operation ID after normalization, got %q and %q", id1, id2)
	}
}
