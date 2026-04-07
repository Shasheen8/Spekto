package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	grpc_testing "google.golang.org/grpc/reflection/grpc_testing"
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
		"discover", "traffic",
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

func TestRunDiscoverTrafficAcceptsPostmanInput(t *testing.T) {
	dir := t.TempDir()

	postmanPath := filepath.Join(dir, "collection.json")
	postmanDoc := `{
	  "item": [
	    {
	      "name": "List models",
	      "request": {
	        "method": "GET",
	        "url": {"raw":"https://api.example.com/v1/models"}
	      }
	    }
	  ]
	}`
	if err := os.WriteFile(postmanPath, []byte(postmanDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(postman) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "inventory.json")
	if err := run([]string{
		"discover", "traffic",
		"--postman", postmanPath,
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
	if payload.Summary.Total != 1 || payload.Summary.ByProtocol["rest"] != 1 {
		t.Fatalf("unexpected summary: %#v", payload.Summary)
	}
}

func TestRunDiscoverTrafficAcceptsAccessLogInput(t *testing.T) {
	dir := t.TempDir()

	logPath := filepath.Join(dir, "access.jsonl")
	logDoc := `{"method":"GET","url":"https://api.example.com/v1/models","status":200}`
	if err := os.WriteFile(logPath, []byte(logDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(access-log) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "inventory.json")
	if err := run([]string{
		"discover", "traffic",
		"--access-log", logPath,
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
	if payload.Summary.Total != 1 || payload.Summary.ByProtocol["rest"] != 1 {
		t.Fatalf("unexpected summary: %#v", payload.Summary)
	}
}

func TestRunDiscoverMergeMergesInventoryFiles(t *testing.T) {
	dir := t.TempDir()

	inventoryAPath := filepath.Join(dir, "inventory-a.json")
	inventoryA := `{
	  "operations": [
	    {
	      "id": "rest-models",
	      "protocol": "rest",
	      "family": "http",
	      "locator": "GET:/v1/models",
	      "display_name": "GET:/v1/models",
	      "provenance": {"specified": true},
	      "confidence": 0.9,
	      "auth_hints": {"requires_auth": "unknown"},
	      "schema_refs": {"responses": {}},
	      "status": "normalized"
	    }
	  ],
	  "summary": {"total": 1}
	}`
	if err := os.WriteFile(inventoryAPath, []byte(inventoryA), 0o600); err != nil {
		t.Fatalf("os.WriteFile(inventoryA) returned error: %v", err)
	}

	inventoryBPath := filepath.Join(dir, "inventory-b.json")
	inventoryB := `{
	  "operations": [
	    {
	      "id": "rest-models",
	      "protocol": "rest",
	      "family": "http",
	      "locator": "GET:/v1/models",
	      "display_name": "List models",
	      "provenance": {"observed": true},
	      "confidence": 0.8,
	      "auth_hints": {"requires_auth": "unknown"},
	      "schema_refs": {"responses": {}},
	      "status": "normalized",
	      "source_refs": [{"type":"traffic","location":"traffic.har"}]
	    },
	    {
	      "id": "graphql-model",
	      "protocol": "graphql",
	      "family": "graphql",
	      "locator": "query:model",
	      "display_name": "query:model",
	      "provenance": {"specified": true},
	      "confidence": 0.7,
	      "auth_hints": {"requires_auth": "unknown"},
	      "schema_refs": {"responses": {}},
	      "status": "normalized"
	    }
	  ],
	  "summary": {"total": 2}
	}`
	if err := os.WriteFile(inventoryBPath, []byte(inventoryB), 0o600); err != nil {
		t.Fatalf("os.WriteFile(inventoryB) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "merged.json")
	if err := run([]string{
		"discover", "merge",
		"--inventory", inventoryAPath,
		"--inventory", inventoryBPath,
		"--out", outPath,
	}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile returned error: %v", err)
	}
	var payload struct {
		Operations []struct {
			ID         string `json:"id"`
			Provenance struct {
				Specified bool `json:"specified"`
				Observed  bool `json:"observed"`
			} `json:"provenance"`
		} `json:"operations"`
		Summary struct {
			Total          int            `json:"total"`
			SpecifiedCount int            `json:"specified_count"`
			ObservedCount  int            `json:"observed_count"`
			ByProtocol     map[string]int `json:"by_protocol"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload.Summary.Total != 2 {
		t.Fatalf("expected total 2, got %d", payload.Summary.Total)
	}
	if payload.Summary.SpecifiedCount != 2 || payload.Summary.ObservedCount != 1 {
		t.Fatalf("unexpected summary: %#v", payload.Summary)
	}
	if payload.Summary.ByProtocol["rest"] != 1 || payload.Summary.ByProtocol["graphql"] != 1 {
		t.Fatalf("unexpected by_protocol: %#v", payload.Summary.ByProtocol)
	}
	for _, op := range payload.Operations {
		if op.ID == "rest-models" && (!op.Provenance.Specified || !op.Provenance.Observed) {
			t.Fatalf("expected merged provenance on rest-models, got %#v", op.Provenance)
		}
	}
}

func TestRunDiscoverManualAcceptsSeedInput(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "manual.yaml")
	seed := `
rest:
  - method: GET
    path: /v1/models
graphql:
  - root_kind: query
    name: model
`
	if err := os.WriteFile(seedPath, []byte(seed), 0o600); err != nil {
		t.Fatalf("os.WriteFile(seed) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "inventory.json")
	if err := run([]string{"discover", "manual", "--seed", seedPath, "--out", outPath}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile returned error: %v", err)
	}
	var payload struct {
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload.Summary.Total != 2 {
		t.Fatalf("expected total 2, got %d", payload.Summary.Total)
	}
}

func TestRunDiscoverActiveAcceptsGRPCReflection(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}
	defer lis.Close()

	server := grpc.NewServer()
	grpc_testing.RegisterSearchServiceServer(server, cliSearchServiceServer{})
	reflection.Register(server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(lis)
	}()
	defer func() {
		server.Stop()
		<-errCh
	}()

	dir := t.TempDir()
	outPath := filepath.Join(dir, "inventory.json")
	if err := run([]string{"discover", "active", "--grpc-reflection", lis.Addr().String(), "--out", outPath}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile returned error: %v", err)
	}
	var payload struct {
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload.Summary.Total != 2 {
		t.Fatalf("expected total 2, got %d", payload.Summary.Total)
	}
}

type cliSearchServiceServer struct {
	grpc_testing.UnimplementedSearchServiceServer
}

func TestRunScanWritesBundle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	cfgPath := filepath.Join(t.TempDir(), "spekto.yaml")
	configDoc := "targets:\n  - name: rest\n    protocol: rest\n    base_url: " + server.URL + "\nscan:\n  concurrency: 1\n  request_budget: 5\n  timeout: 2s\n"
	if err := os.WriteFile(cfgPath, []byte(configDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config) returned error: %v", err)
	}

	operation := inventory.NewRESTOperation(http.MethodGet, "/")
	operation.DisplayName = "root"
	operation.Confidence = 0.9
	operation.Status = inventory.StatusSeedable
	operation.REST = &inventory.RESTDetails{
		Method:         http.MethodGet,
		NormalizedPath: "/",
	}
	invPath := filepath.Join(t.TempDir(), "inventory.json")
	data, err := inventory.Merge([]inventory.Operation{operation}).JSON()
	if err != nil {
		t.Fatalf("inventory JSON returned error: %v", err)
	}
	if err := os.WriteFile(invPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(inventory) returned error: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "bundle.json")
	if err := run([]string{"scan", "--config", cfgPath, "--inventory", invPath, "--out", outPath}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	bundleData, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile(bundle) returned error: %v", err)
	}
	var payload struct {
		Summary struct {
			Total     int `json:"total"`
			Succeeded int `json:"succeeded"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(bundleData, &payload); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if payload.Summary.Total != 1 || payload.Summary.Succeeded != 1 {
		t.Fatalf("unexpected summary: %#v", payload.Summary)
	}
}

func TestTriStateBoolSetParsesTrueAndFalse(t *testing.T) {
	var value triStateBool
	if err := value.Set("true"); err != nil {
		t.Fatalf("Set(true) returned error: %v", err)
	}
	if !value.set || !value.value {
		t.Fatalf("unexpected triStateBool after true: %#v", value)
	}

	value = triStateBool{}
	if err := value.Set("false"); err != nil {
		t.Fatalf("Set(false) returned error: %v", err)
	}
	if !value.set || value.value {
		t.Fatalf("unexpected triStateBool after false: %#v", value)
	}
}
