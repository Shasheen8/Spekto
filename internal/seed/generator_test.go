package seed

import (
	"testing"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestGenerateRESTCandidate_NilREST(t *testing.T) {
	op := inventory.Operation{}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if len(c.PathValues) != 0 || len(c.QueryValues) != 0 || c.Body != nil {
		t.Fatal("expected empty candidate for operation with no REST details")
	}
}

func TestGenerateRESTCandidate_HintTakesPriority(t *testing.T) {
	op := inventory.Operation{
		Examples: inventory.Examples{
			Parameters: []inventory.ParameterValue{
				{Name: "model_id", In: "path", Example: "spec-example"},
			},
		},
		REST: &inventory.RESTDetails{
			Method: "GET",
			PathParams: []inventory.ParameterMeta{
				{Name: "model_id", In: "path", Type: "string"},
			},
		},
	}
	hints := config.ResourceHints{
		PathParams: map[string]string{"model_id": "hint-value"},
	}
	c := GenerateRESTCandidate(op, hints)
	if got := c.PathValues["model_id"]; got != "hint-value" {
		t.Fatalf("expected hint value, got %q", got)
	}
	if len(c.SchemaGaps) != 0 {
		t.Fatal("expected no schema gaps when hint is provided")
	}
}

func TestGenerateRESTCandidate_ConstantFallback(t *testing.T) {
	op := inventory.Operation{
		REST: &inventory.RESTDetails{
			PathParams: []inventory.ParameterMeta{
				{Name: "org_id", In: "path", Type: "string"},
			},
		},
	}
	hints := config.ResourceHints{
		Constants: map[string]string{"org_id": "const-value"},
	}
	c := GenerateRESTCandidate(op, hints)
	if got := c.PathValues["org_id"]; got != "const-value" {
		t.Fatalf("expected constant value, got %q", got)
	}
	if len(c.SchemaGaps) != 0 {
		t.Fatal("expected no schema gaps when constant is provided")
	}
}

func TestGenerateRESTCandidate_ExampleFromInventory(t *testing.T) {
	op := inventory.Operation{
		Examples: inventory.Examples{
			Parameters: []inventory.ParameterValue{
				{Name: "user_id", In: "path", Example: "usr_abc"},
			},
		},
		REST: &inventory.RESTDetails{
			PathParams: []inventory.ParameterMeta{
				{Name: "user_id", In: "path", Type: "string"},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if got := c.PathValues["user_id"]; got != "usr_abc" {
		t.Fatalf("expected inventory example, got %q", got)
	}
	if len(c.SchemaGaps) != 0 {
		t.Fatal("expected no schema gaps when example is available")
	}
}

func TestGenerateRESTCandidate_DefaultFallback(t *testing.T) {
	op := inventory.Operation{
		REST: &inventory.RESTDetails{
			PathParams: []inventory.ParameterMeta{
				{Name: "version", In: "path", Type: "string", Default: "v1"},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if got := c.PathValues["version"]; got != "v1" {
		t.Fatalf("expected default value, got %q", got)
	}
	if len(c.SchemaGaps) != 0 {
		t.Fatal("expected no schema gaps when default is available")
	}
}

func TestGenerateRESTCandidate_EnumFallback(t *testing.T) {
	op := inventory.Operation{
		REST: &inventory.RESTDetails{
			QueryParams: []inventory.ParameterMeta{
				{Name: "status", In: "query", Type: "string", Enum: []string{"active", "inactive"}, Required: true},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if got := c.QueryValues["status"]; got != "active" {
		t.Fatalf("expected first enum value, got %q", got)
	}
	if len(c.SchemaGaps) != 0 {
		t.Fatal("expected no schema gaps when enum is available")
	}
}

func TestGenerateRESTCandidate_TypeFallbackIsSchemaGap(t *testing.T) {
	op := inventory.Operation{
		REST: &inventory.RESTDetails{
			PathParams: []inventory.ParameterMeta{
				{Name: "item_id", In: "path", Type: "string"},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if got := c.PathValues["item_id"]; got != "sample" {
		t.Fatalf("expected type fallback 'sample', got %q", got)
	}
	if len(c.SchemaGaps) != 1 || c.SchemaGaps[0] != "path:item_id" {
		t.Fatalf("expected schema gap for item_id, got %v", c.SchemaGaps)
	}
}

func TestGenerateRESTCandidate_QueryParamInclusion(t *testing.T) {
	op := inventory.Operation{
		REST: &inventory.RESTDetails{
			QueryParams: []inventory.ParameterMeta{
				// Optional with no concrete value: should be skipped (type fallback only).
				{Name: "optional_no_value", In: "query", Type: "string", Required: false},
				// Optional but has a default: should be included.
				{Name: "optional_with_default", In: "query", Type: "string", Required: false, Default: "val"},
				// Required with no concrete value: included with type fallback, recorded as gap.
				{Name: "required_no_value", In: "query", Type: "string", Required: true},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if _, ok := c.QueryValues["optional_no_value"]; ok {
		t.Fatal("expected optional param with no concrete value to be skipped")
	}
	if got := c.QueryValues["optional_with_default"]; got != "val" {
		t.Fatalf("expected default value for optional param, got %q", got)
	}
	if got := c.QueryValues["required_no_value"]; got != "sample" {
		t.Fatalf("expected type fallback for required param, got %q", got)
	}
	foundGap := false
	for _, g := range c.SchemaGaps {
		if g == "query:required_no_value" {
			foundGap = true
		}
	}
	if !foundGap {
		t.Fatal("expected schema gap for required param with no concrete value")
	}
}

func TestGenerateRESTCandidate_BodyFromExample(t *testing.T) {
	op := inventory.Operation{
		Examples: inventory.Examples{
			RequestBodies: []inventory.ExampleValue{
				{MediaType: "application/json", Value: `{"name":"test"}`},
			},
		},
		REST: &inventory.RESTDetails{
			RequestBody: &inventory.RequestBodyMeta{
				Required: true,
				Content:  []inventory.MediaTypeMeta{{MediaType: "application/json"}},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if string(c.Body) != `{"name":"test"}` {
		t.Fatalf("expected body from example, got %q", c.Body)
	}
	if c.ContentType != "application/json" {
		t.Fatalf("expected content type from example, got %q", c.ContentType)
	}
}

func TestGenerateRESTCandidate_BodyFallbackEmptyJSON(t *testing.T) {
	op := inventory.Operation{
		REST: &inventory.RESTDetails{
			RequestBody: &inventory.RequestBodyMeta{
				Required: true,
				Content:  []inventory.MediaTypeMeta{{MediaType: "application/json"}},
			},
		},
	}
	c := GenerateRESTCandidate(op, config.ResourceHints{})
	if string(c.Body) != "{}" {
		t.Fatalf("expected empty JSON fallback, got %q", c.Body)
	}
}

func TestTypeFallback(t *testing.T) {
	cases := []struct {
		typ, format, want string
	}{
		{"string", "uuid", "00000000-0000-0000-0000-000000000000"},
		{"string", "date", "2024-01-01"},
		{"string", "date-time", "2024-01-01T00:00:00Z"},
		{"string", "email", "user@example.com"},
		{"string", "uri", "https://example.com"},
		{"integer", "", "1"},
		{"number", "", "1.0"},
		{"boolean", "", "true"},
		{"array", "", "[]"},
		{"string", "", "sample"},
		{"", "", "sample"},
	}
	for _, tc := range cases {
		got := TypeFallback(tc.typ, tc.format)
		if got != tc.want {
			t.Errorf("TypeFallback(%q, %q) = %q, want %q", tc.typ, tc.format, got, tc.want)
		}
	}
}
