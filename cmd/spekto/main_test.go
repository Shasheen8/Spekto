package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	grpc_testing "google.golang.org/grpc/reflection/grpc_testing"
)

func TestRunVersionPrintsDevVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		output := captureStdout(t, func() error {
			return run(args)
		})
		if output != "dev\n" {
			t.Fatalf("run(%v) printed %q, want dev newline", args, output)
		}
	}
}

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

func TestRunDiscoverSpecPrintsFullInventorySummary(t *testing.T) {
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
        "404":
          description: not found
  /v1/chat/completions:
    post:
      responses:
        "201":
          description: created
        "400":
          description: bad request
  /v1/files/{file_id}:
    delete:
      responses:
        "204":
          description: deleted
`
	if err := os.WriteFile(openapiPath, []byte(openapiDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(openapi) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "inventory.json")
	output := captureStderr(t, func() error {
		return run([]string{
			"discover", "spec",
			"--openapi", openapiPath,
			"--out", outPath,
		})
	})

	for _, want := range []string{
		"Spekto discovery complete",
		"Inventory  3 operations",
		"rest:",
		"Methods",
		"GET",
		"POST",
		"DELETE",
		"Operations",
		"DELETE:/v1/files/{file_id}",
		"status=204",
		"GET:/v1/models",
		"status=200,404",
		"POST:/v1/chat/completions",
		"status=201,400",
		"Artifact",
		outPath,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected discovery output to contain %q, got:\n%s", want, output)
		}
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

func TestRunScanAcceptsOpenAPIAndWritesDefaultArtifacts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "spekto.yaml")
	configDoc := "targets:\n  - name: rest\n    protocol: rest\n    base_url: " + server.URL + "\nscan:\n  concurrency: 1\n  request_budget: 5\n  timeout: 2s\n"
	if err := os.WriteFile(cfgPath, []byte(configDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config) returned error: %v", err)
	}

	openapiPath := filepath.Join(dir, "openapi.yaml")
	openapiDoc := `
openapi: 3.1.0
info:
  title: Test API
  version: 1.0.0
paths:
  /:
    get:
      responses:
        "200":
          description: ok
`
	if err := os.WriteFile(openapiPath, []byte(openapiDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(openapi) returned error: %v", err)
	}

	outDir := filepath.Join(dir, "spekto-artifacts")
	output := captureStderr(t, func() error {
		return run([]string{
			"scan",
			"--config", cfgPath,
			"--openapi", openapiPath,
			"--out-dir", outDir,
			"--no-rules",
		})
	})
	for _, want := range []string{
		"Spekto discovery complete",
		"Spekto scan complete",
		filepath.Join(outDir, "inventory.json"),
		filepath.Join(outDir, "evidence.json"),
		filepath.Join(outDir, "coverage.json"),
		filepath.Join(outDir, "findings.json"),
		filepath.Join(outDir, "spekto.sarif"),
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
	for _, name := range []string{"inventory.json", "evidence.json", "coverage.json", "findings.json", "spekto.sarif"} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("expected artifact %s: %v", name, err)
		}
	}
}

func TestRunScanDryRunHonorsOperationFilter(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "spekto.yaml")
	configDoc := "targets:\n  - name: rest\n    protocol: rest\n    base_url: https://api.example.com\nscan:\n  concurrency: 1\n  request_budget: 5\n  timeout: 2s\n"
	if err := os.WriteFile(cfgPath, []byte(configDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config) returned error: %v", err)
	}

	wanted := inventory.NewRESTOperation(http.MethodGet, "/v1/wanted")
	wanted.Confidence = 0.9
	wanted.Status = inventory.StatusSeedable
	wanted.REST = &inventory.RESTDetails{Method: http.MethodGet, NormalizedPath: "/v1/wanted"}
	other := inventory.NewRESTOperation(http.MethodGet, "/v1/other")
	other.Confidence = 0.9
	other.Status = inventory.StatusSeedable
	other.REST = &inventory.RESTDetails{Method: http.MethodGet, NormalizedPath: "/v1/other"}

	invPath := filepath.Join(dir, "inventory.json")
	data, err := inventory.Merge([]inventory.Operation{wanted, other}).JSON()
	if err != nil {
		t.Fatalf("inventory JSON returned error: %v", err)
	}
	if err := os.WriteFile(invPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(inventory) returned error: %v", err)
	}

	output := captureStderr(t, func() error {
		return run([]string{
			"scan",
			"--config", cfgPath,
			"--inventory", invPath,
			"--operation", "GET:/v1/wanted",
			"--dry-run",
		})
	})
	if !strings.Contains(output, "Inventory (1 of 2 operations selected)") {
		t.Fatalf("expected filtered inventory count, got:\n%s", output)
	}
	if !strings.Contains(output, "GET:/v1/wanted") {
		t.Fatalf("expected dry-run output to include selected operation, got:\n%s", output)
	}
	if strings.Contains(output, "GET:/v1/other") {
		t.Fatalf("dry-run output should not include unselected operation, got:\n%s", output)
	}
}

func TestRunScanNoRulesPrintsSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "spekto.yaml")
	configDoc := "targets:\n  - name: rest\n    protocol: rest\n    base_url: " + server.URL + "\nscan:\n  concurrency: 1\n  request_budget: 5\n  timeout: 2s\n"
	if err := os.WriteFile(cfgPath, []byte(configDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config) returned error: %v", err)
	}

	operation := inventory.NewRESTOperation(http.MethodGet, "/")
	operation.DisplayName = "root"
	operation.Confidence = 0.9
	operation.Status = inventory.StatusSeedable
	operation.REST = &inventory.RESTDetails{Method: http.MethodGet, NormalizedPath: "/"}
	invPath := filepath.Join(dir, "inventory.json")
	data, err := inventory.Merge([]inventory.Operation{operation}).JSON()
	if err != nil {
		t.Fatalf("inventory JSON returned error: %v", err)
	}
	if err := os.WriteFile(invPath, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(inventory) returned error: %v", err)
	}

	outPath := filepath.Join(dir, "bundle.json")
	output := captureStderr(t, func() error {
		return run([]string{"scan", "--config", cfgPath, "--inventory", invPath, "--no-rules", "--out", outPath})
	})
	for _, want := range []string{
		"Spekto scan complete",
		"Coverage  1/1 operations seeded",
		"Rules     skipped (--no-rules)",
		"Artifacts",
		outPath,
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, output)
		}
	}
}

func TestRunScanCapturesSeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "spekto.yaml")
	configDoc := "targets:\n  - name: rest\n    protocol: rest\n    base_url: " + server.URL + "\nscan:\n  concurrency: 1\n  request_budget: 5\n  timeout: 2s\n"
	if err := os.WriteFile(cfgPath, []byte(configDoc), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config) returned error: %v", err)
	}

	operation := inventory.NewRESTOperation(http.MethodGet, "/v1/items")
	operation.DisplayName = "list items"
	operation.Confidence = 0.9
	operation.Status = inventory.StatusSeedable
	operation.REST = &inventory.RESTDetails{
		Method:         http.MethodGet,
		NormalizedPath: "/v1/items",
	}
	invPath := filepath.Join(dir, "inventory.json")
	invData, err := inventory.Merge([]inventory.Operation{operation}).JSON()
	if err != nil {
		t.Fatalf("inventory JSON returned error: %v", err)
	}
	if err := os.WriteFile(invPath, invData, 0o600); err != nil {
		t.Fatalf("os.WriteFile(inventory) returned error: %v", err)
	}

	seedPath := filepath.Join(dir, "seeds.json")
	outPath := filepath.Join(dir, "bundle.json")
	if err := run([]string{"scan", "--config", cfgPath, "--inventory", invPath, "--seed-store", seedPath, "--out", outPath}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	seedData, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("os.ReadFile(seeds) returned error: %v", err)
	}
	var store struct {
		Records []struct {
			OperationID    string `json:"operation_id"`
			ResponseStatus int    `json:"response_status"`
			Source         string `json:"source"`
			URL            string `json:"url"`
		} `json:"records"`
	}
	if err := json.Unmarshal(seedData, &store); err != nil {
		t.Fatalf("json.Unmarshal(seeds) returned error: %v", err)
	}
	if len(store.Records) != 1 {
		t.Fatalf("expected 1 seed record, got %d", len(store.Records))
	}
	rec := store.Records[0]
	if rec.ResponseStatus != http.StatusOK {
		t.Fatalf("expected response_status 200, got %d", rec.ResponseStatus)
	}
	if rec.Source != "scan" {
		t.Fatalf("expected source 'scan', got %q", rec.Source)
	}
	if rec.URL == "" {
		t.Fatal("expected non-empty URL in seed record")
	}

	// Failed results must not be captured.
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failServer.Close()

	cfgPathFail := filepath.Join(dir, "spekto-fail.yaml")
	configDocFail := "targets:\n  - name: rest\n    protocol: rest\n    base_url: " + failServer.URL + "\nscan:\n  concurrency: 1\n  request_budget: 5\n  timeout: 2s\n"
	if err := os.WriteFile(cfgPathFail, []byte(configDocFail), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config-fail) returned error: %v", err)
	}
	seedPathFail := filepath.Join(dir, "seeds-fail.json")
	outPathFail := filepath.Join(dir, "bundle-fail.json")
	if err := run([]string{"scan", "--config", cfgPathFail, "--inventory", invPath, "--seed-store", seedPathFail, "--out", outPathFail}); err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	failData, err := os.ReadFile(seedPathFail)
	if err != nil {
		t.Fatalf("os.ReadFile(seeds-fail) returned error: %v", err)
	}
	var failStore struct {
		Records []struct{} `json:"records"`
	}
	if err := json.Unmarshal(failData, &failStore); err != nil {
		t.Fatalf("json.Unmarshal(seeds-fail) returned error: %v", err)
	}
	if len(failStore.Records) != 0 {
		t.Fatalf("expected 0 seed records for failed scan, got %d", len(failStore.Records))
	}
}

func captureStderr(t *testing.T, fn func() error) string {
	t.Helper()

	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe returned error: %v", err)
	}
	os.Stderr = writer
	err = fn()
	_ = writer.Close()
	os.Stderr = original
	if err != nil {
		t.Fatalf("function returned error: %v", err)
	}
	output, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatalf("io.ReadAll returned error: %v", readErr)
	}
	return string(output)
}

func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()

	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe returned error: %v", err)
	}
	os.Stdout = writer
	err = fn()
	_ = writer.Close()
	os.Stdout = original
	if err != nil {
		t.Fatalf("function returned error: %v", err)
	}
	output, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatalf("io.ReadAll returned error: %v", readErr)
	}
	return string(output)
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
