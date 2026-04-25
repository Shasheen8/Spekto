package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestStatefulScanReportsBOLAWhenAlternateContextCanReadSeedResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/users/alice" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer viewer-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	findings, err := StatefulScan(context.Background(), []executor.Result{
		statefulSeed(http.MethodGet, server.URL+"/users/alice", "owner"),
	}, testStatefulRegistry(t), testStatefulPolicy(), StatefulOptions{})
	if err != nil {
		t.Fatalf("StatefulScan returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != "BOLA001" {
		t.Fatalf("expected BOLA001, got %s", finding.RuleID)
	}
	if finding.Severity != SeverityHigh || finding.Confidence != ConfidenceMedium {
		t.Fatalf("unexpected severity/confidence: %s/%s", finding.Severity, finding.Confidence)
	}
	if finding.Evidence.Probe == nil || finding.Evidence.Probe.Response.StatusCode != http.StatusOK {
		t.Fatalf("expected successful probe evidence, got %#v", finding.Evidence.Probe)
	}
	if !strings.Contains(finding.Description, "viewer") {
		t.Fatalf("expected alternate auth context in description: %s", finding.Description)
	}
}

func TestStatefulScanRequiresWriteOptInForBFLA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/admin/users/alice" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer viewer-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	seeds := []executor.Result{statefulSeed(http.MethodDelete, server.URL+"/admin/users/alice", "owner")}
	findings, err := StatefulScan(context.Background(), seeds, testStatefulRegistry(t), testStatefulPolicy(), StatefulOptions{})
	if err != nil {
		t.Fatalf("StatefulScan returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no BFLA finding without write opt-in, got %d", len(findings))
	}

	findings, err = StatefulScan(context.Background(), seeds, testStatefulRegistry(t), testStatefulPolicy(), StatefulOptions{
		AllowWriteChecks: true,
	})
	if err != nil {
		t.Fatalf("StatefulScan returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.RuleID != "BFLA001" {
		t.Fatalf("expected BFLA001, got %s", finding.RuleID)
	}
	if finding.Evidence.Probe == nil || finding.Evidence.Probe.Response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected successful probe evidence, got %#v", finding.Evidence.Probe)
	}
}

func statefulSeed(method, url, authContext string) executor.Result {
	return executor.Result{
		Protocol:        inventory.ProtocolREST,
		Target:          "test-rest",
		OperationID:     method + ":" + url,
		Locator:         method + ":" + url,
		AuthContextName: authContext,
		Status:          "succeeded",
		Evidence: executor.Evidence{
			Request: executor.RequestEvidence{
				Method: method,
				URL:    url,
			},
			Response: executor.ResponseEvidence{
				StatusCode: http.StatusOK,
			},
		},
	}
}

func testStatefulRegistry(t *testing.T) auth.Registry {
	t.Helper()

	registry, err := auth.NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "owner", BearerToken: "owner-token"},
			{Name: "viewer", BearerToken: "viewer-token"},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}
	return registry
}

func testStatefulPolicy() executor.HTTPPolicy {
	return executor.HTTPPolicy{
		Concurrency:      1,
		RequestBudget:    10,
		Timeout:          time.Second,
		MaxResponseBytes: 1024,
		Budget:           executor.NewRequestBudget(10),
	}
}
