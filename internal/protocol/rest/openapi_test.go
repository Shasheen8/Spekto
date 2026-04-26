package rest

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestDetectVersionFamilies(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		version string
		family  VersionFamily
		level   inventory.SupportLevel
	}{
		{
			name:    "swagger 2",
			doc:     "swagger: '2.0'\ninfo:\n  title: test\n  version: 1.0.0\npaths: {}\n",
			version: "2.0",
			family:  VersionFamilySwagger20,
			level:   inventory.SupportLevelFull,
		},
		{
			name:    "openapi 3.1",
			doc:     "openapi: 3.1.0\ninfo:\n  title: test\n  version: 1.0.0\npaths: {}\n",
			version: "3.1.0",
			family:  VersionFamilyOpenAPI31,
			level:   inventory.SupportLevelFull,
		},
		{
			name:    "openapi 3.2",
			doc:     "openapi: 3.2.0\ninfo:\n  title: test\n  version: 1.0.0\npaths: {}\n",
			version: "3.2.0",
			family:  VersionFamilyOpenAPI32,
			level:   inventory.SupportLevelFull,
		},
		{
			name:    "future openapi",
			doc:     "openapi: 3.9.0\ninfo:\n  title: test\n  version: 1.0.0\npaths: {}\n",
			version: "3.9.0",
			family:  VersionFamily("openapi_future"),
			level:   inventory.SupportLevelPartial,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version, family, level, _, err := detectVersion([]byte(tc.doc))
			if err != nil {
				t.Fatalf("detectVersion returned error: %v", err)
			}
			if version != tc.version {
				t.Fatalf("expected version %q, got %q", tc.version, version)
			}
			if family != tc.family {
				t.Fatalf("expected family %q, got %q", tc.family, family)
			}
			if level != tc.level {
				t.Fatalf("expected support level %q, got %q", tc.level, level)
			}
		})
	}
}

func TestParseDataExtractsRESTOperations(t *testing.T) {
	doc := `
openapi: 3.1.0
info:
  title: Spekto Test
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /v1/models/{model_id}:
    parameters:
      - in: path
        name: model_id
        required: true
        schema:
          type: string
    get:
      operationId: getModel
      tags: [models]
      security:
        - bearerAuth: []
      parameters:
        - in: query
          name: expand
          schema:
            type: string
            enum: [stats]
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Model'
  /v1/models:
    post:
      operationId: createModel
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateModelRequest'
      responses:
        "201":
          description: created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Model'
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  schemas:
    CreateModelRequest:
      type: object
    Model:
      type: object
`

	parsed, err := ParseData(context.Background(), []byte(doc), "spec.yaml")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if parsed.DeclaredVersion != "3.1.0" {
		t.Fatalf("unexpected declared version: %s", parsed.DeclaredVersion)
	}
	if len(parsed.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(parsed.Operations))
	}

	var getOp inventory.Operation
	var postOp inventory.Operation
	for _, op := range parsed.Operations {
		if op.REST == nil {
			continue
		}
		switch {
		case op.REST.Method == "GET" && op.REST.NormalizedPath == "/v1/models/{model_id}":
			getOp = op
		case op.REST.Method == "POST" && op.REST.NormalizedPath == "/v1/models":
			postOp = op
		}
	}
	if getOp.ID == "" {
		t.Fatalf("expected GET operation to be present")
	}
	if postOp.ID == "" {
		t.Fatalf("expected POST operation to be present")
	}

	if getOp.Protocol != inventory.ProtocolREST {
		t.Fatalf("unexpected protocol: %s", getOp.Protocol)
	}
	if getOp.REST == nil {
		t.Fatalf("expected REST details")
	}
	if getOp.REST.Method != "GET" {
		t.Fatalf("unexpected method: %s", getOp.REST.Method)
	}
	if getOp.REST.NormalizedPath != "/v1/models/{model_id}" {
		t.Fatalf("unexpected path: %s", getOp.REST.NormalizedPath)
	}
	if len(getOp.REST.PathParams) != 1 {
		t.Fatalf("expected one path param, got %d", len(getOp.REST.PathParams))
	}
	if getOp.AuthHints.RequiresAuth != inventory.AuthRequirementYes {
		t.Fatalf("expected auth required, got %s", getOp.AuthHints.RequiresAuth)
	}
	if len(getOp.Targets) != 0 {
		t.Fatalf("expected no configured targets in spec output, got %#v", getOp.Targets)
	}
	if len(getOp.Origins) != 1 || getOp.Origins[0] != "https://api.example.com" {
		t.Fatalf("unexpected origins: %#v", getOp.Origins)
	}

	if postOp.REST == nil || postOp.REST.RequestBody == nil {
		t.Fatalf("expected request body metadata on POST operation")
	}
	if postOp.SchemaRefs.Request != "#/components/schemas/CreateModelRequest" {
		t.Fatalf("unexpected request schema ref: %s", postOp.SchemaRefs.Request)
	}
	if postOp.SchemaRefs.Responses["201"] != "#/components/schemas/Model" {
		t.Fatalf("unexpected response schema ref: %s", postOp.SchemaRefs.Responses["201"])
	}
}

func TestParseDataExtractsSchemaSnapshots(t *testing.T) {
	doc := `
openapi: 3.1.0
info:
  title: Schema Snapshot Test
  version: 1.0.0
paths:
  /v1/users:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                required: [id, role]
                properties:
                  id:
                    type: string
                  role:
                    type: string
                    enum: [user, admin]
                  tags:
                    type: array
                    items:
                      type: string
components: {}
`

	parsed, err := ParseData(context.Background(), []byte(doc), "spec.yaml")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if len(parsed.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(parsed.Operations))
	}

	op := parsed.Operations[0]
	if op.REST == nil || len(op.REST.ResponseMap) != 1 || len(op.REST.ResponseMap[0].Content) != 1 {
		t.Fatalf("expected response content metadata, got %#v", op.REST)
	}
	schema := op.REST.ResponseMap[0].Content[0].Schema
	if schema == nil {
		t.Fatalf("expected response schema snapshot")
	}
	if schema.Type != "object" {
		t.Fatalf("expected object schema, got %#v", schema)
	}
	if len(schema.Required) != 2 || schema.Required[0] != "id" || schema.Required[1] != "role" {
		t.Fatalf("unexpected required fields: %#v", schema.Required)
	}
	role := schema.Properties["role"]
	if role.Type != "string" || len(role.Enum) != 2 || role.Enum[1] != "admin" {
		t.Fatalf("unexpected role schema: %#v", role)
	}
	tags := schema.Properties["tags"]
	if tags.Type != "array" || tags.Items == nil || tags.Items.Type != "string" {
		t.Fatalf("unexpected tags schema: %#v", tags)
	}
}

func TestParseDataExtractsRequestSchemaSnapshots(t *testing.T) {
	doc := `
openapi: 3.1.0
info:
  title: Request Schema Snapshot Test
  version: 1.0.0
paths:
  /v1/users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email:
                  type: string
                  format: email
                role:
                  type: string
                  enum: [user, admin]
      responses:
        "201":
          description: created
components: {}
`

	parsed, err := ParseData(context.Background(), []byte(doc), "spec.yaml")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if len(parsed.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(parsed.Operations))
	}

	body := parsed.Operations[0].REST.RequestBody
	if body == nil || len(body.Content) != 1 {
		t.Fatalf("expected request body metadata, got %#v", body)
	}
	schema := body.Content[0].Schema
	if schema == nil {
		t.Fatalf("expected request schema snapshot")
	}
	if schema.Type != "object" || len(schema.Required) != 1 || schema.Required[0] != "email" {
		t.Fatalf("unexpected request schema: %#v", schema)
	}
	email := schema.Properties["email"]
	if email.Type != "string" || email.Format != "email" {
		t.Fatalf("unexpected email schema: %#v", email)
	}
	role := schema.Properties["role"]
	if len(role.Enum) != 2 || role.Enum[0] != "user" || role.Enum[1] != "admin" {
		t.Fatalf("unexpected role enum: %#v", role.Enum)
	}
}

func TestParseSwaggerTwoConvertsToOperations(t *testing.T) {
	doc := `
swagger: "2.0"
info:
  title: Spekto Swagger Test
  version: 1.0.0
host: api.example.com
basePath: /api
schemes:
  - https
paths:
  /v1/health:
    get:
      responses:
        200:
          description: ok
`

	parsed, err := ParseData(context.Background(), []byte(doc), "swagger.yaml")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if parsed.DeclaredVersion != "2.0" {
		t.Fatalf("unexpected version: %s", parsed.DeclaredVersion)
	}
	if len(parsed.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(parsed.Operations))
	}
	op := parsed.Operations[0]
	if len(op.Origins) != 1 || op.Origins[0] != "https://api.example.com/api" {
		t.Fatalf("unexpected server candidates: %#v", op.Origins)
	}
	if op.REST == nil || op.REST.NormalizedPath != "/v1/health" {
		t.Fatalf("unexpected normalized path")
	}
}

func TestParseDataClassifiesSecuritySchemeComponents(t *testing.T) {
	doc := `
openapi: 3.1.0
info:
  title: Auth Scheme Test
  version: 1.0.0
paths:
  /v1/private:
    get:
      security:
        - customerAccess: []
      responses:
        "200":
          description: ok
components:
  securitySchemes:
    customerAccess:
      type: apiKey
      in: header
      name: X-Customer-Access
`

	parsed, err := ParseData(context.Background(), []byte(doc), "spec.yaml")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if len(parsed.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(parsed.Operations))
	}
	schemes := parsed.Operations[0].AuthHints.AuthSchemes
	if len(schemes) != 1 || schemes[0] != inventory.AuthSchemeAPIKeyHeader {
		t.Fatalf("expected api key header auth scheme, got %#v", schemes)
	}
}

func TestParseFileRejectsLocalExternalRefsByDefault(t *testing.T) {
	dir := t.TempDir()
	componentsPath := filepath.Join(dir, "schemas.yaml")
	componentsDoc := `
Model:
  type: object
`
	if err := os.WriteFile(componentsPath, []byte(componentsDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(components) returned error: %v", err)
	}

	specPath := filepath.Join(dir, "openapi.yaml")
	specDoc := `
openapi: 3.1.0
info:
  title: External Ref Test
  version: 1.0.0
paths:
  /v1/models:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                $ref: './schemas.yaml#/Model'
`
	if err := os.WriteFile(specPath, []byte(specDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(spec) returned error: %v", err)
	}

	if _, err := ParseFile(context.Background(), specPath); err == nil {
		t.Fatalf("expected external file ref to be rejected")
	}
}

func TestParseDataEmitsCallbackWarnings(t *testing.T) {
	doc := `
openapi: 3.1.0
info:
  title: Callback Test
  version: 1.0.0
paths:
  /v1/models:
    post:
      callbacks:
        onEvent:
          '{$request.body#/callbackUrl}':
            post:
              responses:
                "200":
                  description: ok
      responses:
        "202":
          description: accepted
`

	parsed, err := ParseData(context.Background(), []byte(doc), "spec.yaml")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if len(parsed.Warnings) == 0 {
		t.Fatalf("expected callback warning")
	}
}
