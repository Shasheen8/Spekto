package graphql

import (
	"testing"

	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestParseSDLExtractsOperations(t *testing.T) {
	sdl := `
		type Query {
			model(id: ID!): Model
			models(limit: Int): [Model!]!
		}

		type Mutation {
			createModel(input: CreateModelInput!): Model!
		}

		type Model {
			id: ID!
			name: String!
		}

		input CreateModelInput {
			name: String!
		}
	`

	doc, err := ParseData([]byte(sdl), "schema.graphql")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if doc.SourceKind != SourceKindSDL {
		t.Fatalf("unexpected source kind: %s", doc.SourceKind)
	}
	if doc.SchemaStats.QueryCount != 2 {
		t.Fatalf("expected 2 query fields, got %d", doc.SchemaStats.QueryCount)
	}
	if doc.SchemaStats.MutationCount != 1 {
		t.Fatalf("expected 1 mutation field, got %d", doc.SchemaStats.MutationCount)
	}
	if len(doc.Operations) != 3 {
		t.Fatalf("expected 3 operations, got %d", len(doc.Operations))
	}

	var create inventory.Operation
	for _, op := range doc.Operations {
		if op.GraphQL != nil && op.GraphQL.RootKind == "mutation" && op.GraphQL.OperationName == "createModel" {
			create = op
			break
		}
	}
	if create.ID == "" {
		t.Fatalf("expected createModel mutation to be present")
	}
	if create.Protocol != inventory.ProtocolGraphQL {
		t.Fatalf("unexpected protocol: %s", create.Protocol)
	}
	if create.GraphQL == nil {
		t.Fatalf("expected graphql details")
	}
	if len(create.GraphQL.ArgumentMap) != 1 || create.GraphQL.ArgumentMap[0] != "input:CreateModelInput!" {
		t.Fatalf("unexpected argument map: %#v", create.GraphQL.ArgumentMap)
	}
	if len(create.GraphQL.TypeDeps) != 1 || create.GraphQL.TypeDeps[0] != "Model!" {
		t.Fatalf("unexpected type dependencies: %#v", create.GraphQL.TypeDeps)
	}
	if len(create.GraphQL.SelectionHints) != 2 || create.GraphQL.SelectionHints[0] != "id" || create.GraphQL.SelectionHints[1] != "name" {
		t.Fatalf("unexpected selection hints: %#v", create.GraphQL.SelectionHints)
	}
}

func TestParseIntrospectionExtractsOperations(t *testing.T) {
	introspection := `{
	  "data": {
	    "__schema": {
	      "queryType": {"name": "Query"},
	      "mutationType": {"name": "Mutation"},
	      "subscriptionType": null,
	      "types": [
	        {
	          "kind": "OBJECT",
	          "name": "Query",
	          "fields": [
	            {
	              "name": "model",
	              "args": [
	                {
	                  "name": "id",
	                  "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}},
	                  "defaultValue": null
	                }
	              ],
	              "type": {"kind": "OBJECT", "name": "Model", "ofType": null}
	            }
	          ]
	        },
	        {
	          "kind": "OBJECT",
	          "name": "Mutation",
	          "fields": [
	            {
	              "name": "deleteModel",
	              "args": [
	                {
	                  "name": "id",
	                  "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}},
	                  "defaultValue": null
	                }
	              ],
	              "type": {"kind": "SCALAR", "name": "Boolean", "ofType": null}
	            }
	          ]
	        },
	        {
	          "kind": "OBJECT",
	          "name": "Model",
	          "fields": [
	            {
	              "name": "id",
	              "args": [],
	              "type": {"kind": "NON_NULL", "name": null, "ofType": {"kind": "SCALAR", "name": "ID", "ofType": null}}
	            }
	          ]
	        }
	      ]
	    }
	  }
	}`

	doc, err := ParseData([]byte(introspection), "schema.json")
	if err != nil {
		t.Fatalf("ParseData returned error: %v", err)
	}
	if doc.SourceKind != SourceKindIntrospection {
		t.Fatalf("unexpected source kind: %s", doc.SourceKind)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}

	var query inventory.Operation
	for _, op := range doc.Operations {
		if op.GraphQL != nil && op.GraphQL.RootKind == "query" && op.GraphQL.OperationName == "model" {
			query = op
			break
		}
	}
	if query.ID == "" {
		t.Fatalf("expected query operation to be present")
	}
	if query.GraphQL == nil {
		t.Fatalf("expected graphql details")
	}
	if len(query.GraphQL.ArgumentMap) != 1 || query.GraphQL.ArgumentMap[0] != "id:ID!" {
		t.Fatalf("unexpected argument map: %#v", query.GraphQL.ArgumentMap)
	}
	if len(query.GraphQL.TypeDeps) != 1 || query.GraphQL.TypeDeps[0] != "Model" {
		t.Fatalf("unexpected type deps: %#v", query.GraphQL.TypeDeps)
	}
	if len(query.GraphQL.SelectionHints) != 1 || query.GraphQL.SelectionHints[0] != "id" {
		t.Fatalf("unexpected selection hints: %#v", query.GraphQL.SelectionHints)
	}
	if query.Provenance.Specified != true {
		t.Fatalf("expected specified provenance")
	}
}
