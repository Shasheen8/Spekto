package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunDiscoverSpecWritesMergedInventory(t *testing.T) {
	dir := t.TempDir()

	openapiPath := filepath.Join(dir, "openapi.yaml")
	openapiDoc := `
openapi: 3.1.0
info:
  title: Test API
  version: 1.0.0
paths:
  /v1/models:
    get:
      responses:
        "200":
          description: ok
`
	if err := os.WriteFile(openapiPath, []byte(openapiDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(openapi) returned error: %v", err)
	}

	graphQLPath := filepath.Join(dir, "schema.graphql")
	graphQLDoc := `
type Query {
  model(id: ID!): Model
}

type Model {
  id: ID!
}
`
	if err := os.WriteFile(graphQLPath, []byte(graphQLDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(graphql) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "inventory.json")
	if err := run([]string{
		"discover", "spec",
		"--openapi", openapiPath,
		"--graphql-schema", graphQLPath,
		"--out", outPath,
	}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile returned error: %v", err)
	}
	var payload struct {
		Summary struct {
			Total      int            `json:"total"`
			ByProtocol map[string]int `json:"by_protocol"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload.Summary.Total != 2 {
		t.Fatalf("expected total 2, got %d", payload.Summary.Total)
	}
	if payload.Summary.ByProtocol["rest"] != 1 {
		t.Fatalf("expected one rest operation, got %d", payload.Summary.ByProtocol["rest"])
	}
	if payload.Summary.ByProtocol["graphql"] != 1 {
		t.Fatalf("expected one graphql operation, got %d", payload.Summary.ByProtocol["graphql"])
	}
}

func TestRunDiscoverSpecAcceptsHARInput(t *testing.T) {
	dir := t.TempDir()

	harPath := filepath.Join(dir, "traffic.har")
	harDoc := `{
	  "log": {
	    "entries": [
	      {
	        "request": {
	          "method": "GET",
	          "url": "https://api.example.com/v1/models?id=model_1",
	          "headers": [],
	          "queryString": [{"name":"id","value":"model_1"}]
	        },
	        "response": {
	          "status": 200,
	          "content": {"mimeType":"application/json"}
	        }
	      }
	    ]
	  }
	}`
	if err := os.WriteFile(harPath, []byte(harDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(har) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "inventory.json")
	if err := run([]string{
		"discover", "spec",
		"--har", harPath,
		"--out", outPath,
	}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile returned error: %v", err)
	}
	var payload struct {
		Summary struct {
			Total      int            `json:"total"`
			ByProtocol map[string]int `json:"by_protocol"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload.Summary.Total != 1 {
		t.Fatalf("expected total 1, got %d", payload.Summary.Total)
	}
	if payload.Summary.ByProtocol["rest"] != 1 {
		t.Fatalf("expected one rest operation from HAR, got %d", payload.Summary.ByProtocol["rest"])
	}
}
