package executor

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
	grpcdiscovery "github.com/Shasheen8/Spekto/internal/protocol/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	grpc_testing "google.golang.org/grpc/reflection/grpc_testing"
)

func TestScanRESTTargetProducesBundle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models/sample" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "1" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer server.Close()

	operation := inventory.NewRESTOperation(http.MethodGet, "/v1/models/{id}")
	operation.DisplayName = "List model"
	operation.Confidence = 0.9
	operation.Status = inventory.StatusSeedable
	operation.REST = &inventory.RESTDetails{
		Method:         http.MethodGet,
		NormalizedPath: "/v1/models/{id}",
		PathParams: []inventory.ParameterMeta{{
			Name: "id", In: "path", Type: "string",
		}},
		QueryParams: []inventory.ParameterMeta{{
			Name: "limit", In: "query", Type: "integer", Default: "1",
		}},
	}

	cfg := config.Config{
		Targets: []config.Target{{
			Name:     "rest",
			Protocol: "rest",
			BaseURL:  server.URL,
		}},
		Scan: config.ScanPolicy{
			Concurrency:      1,
			RequestBudget:    5,
			Timeout:          2 * time.Second,
			MaxResponseBytes: 1024,
		},
	}

	bundle, err := Scan(context.Background(), cfg, inventory.Merge([]inventory.Operation{operation}), ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if bundle.Summary.Total != 1 || bundle.Summary.Succeeded != 1 {
		t.Fatalf("unexpected summary: %#v", bundle.Summary)
	}
	if bundle.Results[0].Evidence.Response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", bundle.Results[0].Evidence.Response.StatusCode)
	}
}

func TestScanGraphQLTargetProducesGraphQLQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("json decode returned error: %v", err)
		}
		if payload.Query != `query { model(id: "00000000-0000-0000-0000-000000000000") { id } }` {
			t.Fatalf("unexpected graphql query: %s", payload.Query)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"model":{"id":"1"}}}`))
	}))
	defer server.Close()

	operation := inventory.Operation{
		ID:          "graphql-model",
		Protocol:    inventory.ProtocolGraphQL,
		Family:      inventory.FamilyGraphQL,
		Locator:     "query:model(id:ID!)",
		DisplayName: "query:model",
		Confidence:  0.9,
		AuthHints: inventory.AuthHints{
			RequiresAuth: inventory.AuthRequirementUnknown,
		},
		SchemaRefs: inventory.SchemaRefs{Responses: map[string]string{}},
		Status:     inventory.StatusNormalized,
		GraphQL: &inventory.GraphQLDetails{
			RootKind:       "query",
			OperationName:  "model",
			ArgumentMap:    []string{"id:ID!"},
			SelectionHints: []string{"id"},
		},
	}

	cfg := config.Config{
		Targets: []config.Target{{
			Name:     "graphql",
			Protocol: "graphql",
			Endpoint: server.URL,
		}},
		Scan: config.ScanPolicy{
			Concurrency:      1,
			RequestBudget:    5,
			Timeout:          2 * time.Second,
			MaxResponseBytes: 1024,
		},
	}

	bundle, err := Scan(context.Background(), cfg, inventory.Merge([]inventory.Operation{operation}), ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if bundle.Summary.Total != 1 || bundle.Summary.Succeeded != 1 {
		t.Fatalf("unexpected summary: %#v", bundle.Summary)
	}
}

func TestScanHTTPMarksUnauthorizedResponseFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	operation := inventory.NewRESTOperation(http.MethodGet, "/v1/private")
	operation.Confidence = 0.9
	operation.Status = inventory.StatusSeedable
	operation.REST = &inventory.RESTDetails{
		Method:         http.MethodGet,
		NormalizedPath: "/v1/private",
	}

	cfg := config.Config{
		Targets: []config.Target{{
			Name:     "rest",
			Protocol: "rest",
			BaseURL:  server.URL,
		}},
		Scan: config.ScanPolicy{
			Concurrency:      1,
			RequestBudget:    5,
			Timeout:          2 * time.Second,
			MaxResponseBytes: 1024,
		},
	}

	bundle, err := Scan(context.Background(), cfg, inventory.Merge([]inventory.Operation{operation}), ScanOptions{})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if bundle.Summary.Succeeded != 0 || bundle.Summary.Failed != 1 {
		t.Fatalf("unexpected summary: %#v", bundle.Summary)
	}
	if bundle.Results[0].Status != "failed" {
		t.Fatalf("expected failed result, got %s", bundle.Results[0].Status)
	}
}

type scanSearchServiceServer struct {
	grpc_testing.UnimplementedSearchServiceServer
}

func (scanSearchServiceServer) Search(context.Context, *grpc_testing.SearchRequest) (*grpc_testing.SearchResponse, error) {
	return &grpc_testing.SearchResponse{}, nil
}

func TestExecuteGRPCRunsUnaryMethod(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}
	defer lis.Close()

	server := grpc.NewServer()
	grpc_testing.RegisterSearchServiceServer(server, scanSearchServiceServer{})
	reflection.Register(server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(lis)
	}()
	defer func() {
		server.Stop()
		<-errCh
	}()

	doc, err := grpcdiscovery.ParseReflectionTarget(context.Background(), lis.Addr().String())
	if err != nil {
		t.Fatalf("ParseReflectionTarget returned error: %v", err)
	}
	var operations []inventory.Operation
	for _, operation := range doc.Operations {
		if operation.GRPC != nil && operation.GRPC.StreamingMode == "unary" {
			operations = append(operations, operation)
		}
	}
	if len(operations) == 0 {
		t.Fatalf("expected at least one unary operation")
	}

	results, err := ExecuteGRPC(context.Background(), config.Target{
		Name:     "grpc",
		Protocol: "grpc",
		Endpoint: lis.Addr().String(),
	}, operations, auth.Registry{}, HTTPPolicy{
		Concurrency:      1,
		RequestBudget:    5,
		Timeout:          time.Second,
		MaxResponseBytes: 1024,
	}, nil)
	if err != nil {
		t.Fatalf("ExecuteGRPC returned error: %v", err)
	}
	if len(results) == 0 || results[0].Status != "succeeded" {
		t.Fatalf("unexpected results: %#v", results)
	}
	if results[0].Evidence.Response.GRPCCode != "OK" {
		t.Fatalf("unexpected grpc code: %s", results[0].Evidence.Response.GRPCCode)
	}
}
