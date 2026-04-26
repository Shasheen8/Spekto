package schema

import (
	"testing"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestValidateBundleFindsUndocumentedStatus(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(201, `{"id":"u1"}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA001" {
		t.Fatalf("expected SCHEMA001, got %#v", findings)
	}
}

func TestValidateBundleFindsResponseSchemaMismatch(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":42,"role":"user","tags":["one"]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected SCHEMA002, got %#v", findings)
	}
}

func TestValidateBundleMatchesOpenAPIStatusRanges(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("2XX", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(201, `{"id":"u1","role":"user","tags":[]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 0 {
		t.Fatalf("expected 2XX response schema to match HTTP 201, got %#v", findings)
	}
}

func TestValidateBundleUsesDefaultResponseSchema(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("default", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(202, `{"id":"u1","role":"user","tags":[]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 0 {
		t.Fatalf("expected default response schema to validate HTTP 202, got %#v", findings)
	}
}

func TestValidateBundleMatchesVendorJSONMediaTypes(t *testing.T) {
	op := operationWithSchema("200", objectSchema())
	op.REST.ResponseMap[0].Content[0].MediaType = "application/problem+json"
	inv := inventory.Inventory{Operations: []inventory.Operation{op}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResultWithContentType(200, "application/vnd.api+json; charset=utf-8", `{"id":"u1","role":"user","tags":[]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 0 {
		t.Fatalf("expected +json media types to match, got %#v", findings)
	}
}

func TestValidateBundleHonorsNullableFields(t *testing.T) {
	schema := objectSchema()
	schema.Properties["nickname"] = inventory.SchemaMeta{Type: "string", Nullable: true}
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", schema)}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","role":"user","tags":[],"nickname":null}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 0 {
		t.Fatalf("expected nullable field to accept null, got %#v", findings)
	}

	schema.Properties["nickname"] = inventory.SchemaMeta{Type: "string"}
	bundle = executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","role":"user","tags":[],"nickname":null}`)}}
	bundle.Finalize()
	findings = ValidateBundle(&bundle, inv)
	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected non-nullable null to produce SCHEMA002, got %#v", findings)
	}
}

func TestValidateBundlePrimitiveTypeValidation(t *testing.T) {
	schema := objectSchema()
	schema.Properties["age"] = inventory.SchemaMeta{Type: "integer"}
	schema.Properties["score"] = inventory.SchemaMeta{Type: "number"}
	schema.Properties["active"] = inventory.SchemaMeta{Type: "boolean"}
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", schema)}}

	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","role":"user","tags":[],"age":1,"score":1.5,"active":true}`)}}
	bundle.Finalize()
	if findings := ValidateBundle(&bundle, inv); len(findings) != 0 {
		t.Fatalf("expected valid primitive values, got %#v", findings)
	}

	bundle = executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","role":"user","tags":[],"age":1.5,"score":1,"active":"true"}`)}}
	bundle.Finalize()
	findings := ValidateBundle(&bundle, inv)
	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected invalid primitive values to produce SCHEMA002, got %#v", findings)
	}
}

func TestValidateBundleFindsEnumMismatch(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","role":"owner","tags":[]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected SCHEMA002 for enum mismatch, got %#v", findings)
	}
}

func TestValidateBundleFindsArrayItemMismatch(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","role":"user","tags":[42]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected SCHEMA002 for array item mismatch, got %#v", findings)
	}
}

func TestValidateBundleFindsMalformedJSON(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected SCHEMA002 for malformed JSON, got %#v", findings)
	}
}

func TestValidateBundleFindsMissingRequiredAndSensitiveFields(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1","password_hash":"secret"}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA003" {
		t.Fatalf("expected SCHEMA003, got %#v", findings)
	}
}

func TestValidateBundleFindsContentTypeMismatch(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithSchema("200", objectSchema())}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResultWithContentType(200, "text/plain", `{"id":"u1","role":"user","tags":[]}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 1 || findings[0].RuleID != "SCHEMA002" {
		t.Fatalf("expected SCHEMA002 for content type mismatch, got %#v", findings)
	}
}

func TestValidateBundleRecordsGapsWhenSchemaCannotRun(t *testing.T) {
	inv := inventory.Inventory{Operations: []inventory.Operation{operationWithoutSchema()}}
	bundle := executor.Bundle{Results: []executor.Result{successfulResult(200, `{"id":"u1"}`)}}
	bundle.Finalize()

	findings := ValidateBundle(&bundle, inv)

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
	if len(bundle.Results[0].SchemaGaps) == 0 {
		t.Fatalf("expected result schema gap")
	}
	if len(bundle.Coverage.Entries) != 1 || len(bundle.Coverage.Entries[0].SchemaGaps) == 0 {
		t.Fatalf("expected coverage schema gap, got %#v", bundle.Coverage)
	}
}

func operationWithSchema(status string, schema *inventory.SchemaMeta) inventory.Operation {
	op := inventory.NewRESTOperation("GET", "/v1/users")
	op.Protocol = inventory.ProtocolREST
	op.REST = &inventory.RESTDetails{
		Method:         "GET",
		NormalizedPath: "/v1/users",
		ResponseMap: []inventory.ResponseMeta{{
			StatusCode: status,
			Content: []inventory.MediaTypeMeta{{
				MediaType: "application/json",
				Schema:    schema,
			}},
		}},
	}
	return op
}

func operationWithoutSchema() inventory.Operation {
	op := operationWithSchema("200", nil)
	op.REST.ResponseMap[0].Content[0].Schema = nil
	return op
}

func objectSchema() *inventory.SchemaMeta {
	return &inventory.SchemaMeta{
		Type:     "object",
		Required: []string{"id", "role"},
		Properties: map[string]inventory.SchemaMeta{
			"id":   {Type: "string"},
			"role": {Type: "string", Enum: []string{"user", "admin"}},
			"tags": {Type: "array", Items: &inventory.SchemaMeta{Type: "string"}},
		},
	}
}

func successfulResult(status int, body string) executor.Result {
	return successfulResultWithContentType(status, "application/json", body)
}

func successfulResultWithContentType(status int, contentType string, body string) executor.Result {
	op := inventory.NewRESTOperation("GET", "/v1/users")
	return executor.Result{
		Protocol:    inventory.ProtocolREST,
		Target:      "rest-api",
		OperationID: op.ID,
		Locator:     op.Locator,
		Status:      "succeeded",
		Evidence: executor.Evidence{
			Request: executor.RequestEvidence{
				Method: "GET",
				URL:    "https://api.example.com/v1/users",
			},
			Response: executor.ResponseEvidence{
				StatusCode: status,
				Headers:    map[string]string{"Content-Type": contentType},
				Body:       []byte(body),
			},
		},
	}
}
