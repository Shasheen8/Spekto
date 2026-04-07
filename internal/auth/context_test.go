package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestNewRegistryBuildsContexts(t *testing.T) {
	cfg := config.Config{
		AuthContexts: []config.AuthContext{
			{
				Name:             "bearer-prod",
				BearerToken:      "token-1",
				Headers:          map[string]string{"X-Tenant": "prod"},
				Cookies:          map[string]string{"session": "abc"},
				APIKeyHeaderName: "X-API-Key",
				APIKeyValue:      "key-1",
				Roles:            []string{"admin"},
			},
		},
	}

	registry, err := NewRegistry(cfg)
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}
	if len(registry.Contexts) != 1 {
		t.Fatalf("expected 1 context, got %d", len(registry.Contexts))
	}
	if registry.Contexts[0].Name != "bearer-prod" {
		t.Fatalf("unexpected name: %s", registry.Contexts[0].Name)
	}
	if registry.Contexts[0].Headers["X-API-Key"] != "key-1" {
		t.Fatalf("expected API key header to be populated")
	}
}

func TestContextApplyHTTPRequestSetsHeadersCookiesAndQuery(t *testing.T) {
	ctx := Context{
		Name:             "api",
		BearerToken:      "token-1",
		Headers:          map[string]string{"X-Tenant": "prod"},
		Cookies:          map[string]string{"session": "cookie-1"},
		APIKeyQueryName:  "api_key",
		APIKeyValue:      "key-1",
		APIKeyHeaderName: "X-API-Key",
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	if err != nil {
		t.Fatalf("http.NewRequest returned error: %v", err)
	}
	if err := ctx.ApplyHTTPRequest(req); err != nil {
		t.Fatalf("ApplyHTTPRequest returned error: %v", err)
	}
	if req.Header.Get("Authorization") != "Bearer token-1" {
		t.Fatalf("unexpected authorization header: %s", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-Tenant") != "prod" {
		t.Fatalf("unexpected tenant header: %s", req.Header.Get("X-Tenant"))
	}
	if req.Header.Get("X-API-Key") != "key-1" {
		t.Fatalf("unexpected api key header: %s", req.Header.Get("X-API-Key"))
	}
	if req.URL.Query().Get("api_key") != "key-1" {
		t.Fatalf("unexpected query api key: %s", req.URL.Query().Get("api_key"))
	}
	cookies := req.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].Value != "cookie-1" {
		t.Fatalf("unexpected cookies: %#v", cookies)
	}
}

func TestContextHTTPHeadersUsesBasicAuthWhenPresent(t *testing.T) {
	ctx := Context{
		BasicUsername: "user",
		BasicPassword: "pass",
	}
	headers := ctx.HTTPHeaders()
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if headers.Get("Authorization") != expected {
		t.Fatalf("unexpected authorization header: %s", headers.Get("Authorization"))
	}
}

func TestCandidatesMatchHintedSchemes(t *testing.T) {
	registry, err := NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "bearer", BearerToken: "token"},
			{Name: "basic", BasicUsername: "user", BasicPassword: "pass"},
			{Name: "cookie", Cookies: map[string]string{"session": "abc"}},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	candidates := registry.Candidates(inventory.AuthHints{
		RequiresAuth: inventory.AuthRequirementYes,
		AuthSchemes:  []inventory.AuthScheme{inventory.AuthSchemeBasic},
	})
	if len(candidates) != 1 || candidates[0] != "basic" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestCandidatesForTargetAppliesAllowlist(t *testing.T) {
	registry, err := NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "bearer", BearerToken: "token"},
			{Name: "basic", BasicUsername: "user", BasicPassword: "pass"},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	candidates, err := registry.CandidatesForTarget(
		inventory.AuthHints{RequiresAuth: inventory.AuthRequirementUnknown},
		config.Target{Name: "api", AuthContexts: []string{"basic"}},
		nil,
	)
	if err != nil {
		t.Fatalf("CandidatesForTarget returned error: %v", err)
	}
	if len(candidates) != 1 || candidates[0] != "basic" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestCandidatesForTargetIntersectsTargetAndSelectedContexts(t *testing.T) {
	registry, err := NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "bearer", BearerToken: "token"},
			{Name: "basic", BasicUsername: "user", BasicPassword: "pass"},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	candidates, err := registry.CandidatesForTarget(
		inventory.AuthHints{RequiresAuth: inventory.AuthRequirementUnknown},
		config.Target{Name: "api", AuthContexts: []string{"basic"}},
		[]string{"bearer"},
	)
	if err != nil {
		t.Fatalf("CandidatesForTarget returned error: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected no intersecting candidates, got %#v", candidates)
	}
}

func TestSupportedSchemesIgnoreGenericHeaders(t *testing.T) {
	ctx := Context{
		Name:    "tenant",
		Headers: map[string]string{"X-Tenant": "prod"},
	}
	if schemes := ctx.SupportedSchemes(); len(schemes) != 0 {
		t.Fatalf("expected no auth schemes for generic headers, got %#v", schemes)
	}
}

func TestResolveLoginFlowsCapturesBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected content type: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"login-token"}`))
	}))
	defer server.Close()

	registry, err := NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{{
			Name: "login",
			Login: &config.LoginFlow{
				Method:      http.MethodPost,
				URL:         server.URL,
				Body:        `{"username":"test"}`,
				ContentType: "application/json",
				Capture: config.LoginCapture{
					BearerJSONPointer: "/token",
				},
			},
		}},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	resolved, err := registry.ResolveLoginFlows(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("ResolveLoginFlows returned error: %v", err)
	}
	ctx, ok := resolved.Get("login")
	if !ok {
		t.Fatalf("expected resolved context")
	}
	if ctx.BearerToken != "login-token" {
		t.Fatalf("unexpected bearer token: %s", ctx.BearerToken)
	}
}

func TestRedactURLMasksQueryAPIKey(t *testing.T) {
	redacted := RedactURL("https://api.example.com/v1/models?api_key=secret&id=1", Context{
		APIKeyQueryName: "api_key",
	})
	if !strings.Contains(redacted, "api_key=%5Bredacted%5D") {
		t.Fatalf("unexpected redacted url: %s", redacted)
	}
}
