package auth

import (
	"net/http"
	"testing"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestNewRegistryBuildsContexts(t *testing.T) {
	cfg := config.Config{
		AuthContexts: []config.AuthContext{
			{
				Name:        "bearer-prod",
				BearerToken: "token-1",
				Headers:     map[string]string{"X-Tenant": "prod"},
				Cookies:     map[string]string{"session": "abc"},
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
}

func TestContextApplyHTTPRequestSetsHeadersAndCookies(t *testing.T) {
	ctx := Context{
		Name:        "api",
		BearerToken: "token-1",
		Headers:     map[string]string{"X-Tenant": "prod"},
		Cookies:     map[string]string{"session": "cookie-1"},
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
	cookies := req.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].Value != "cookie-1" {
		t.Fatalf("unexpected cookies: %#v", cookies)
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

func TestCandidatesReturnExplicitHintedNames(t *testing.T) {
	registry, err := NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "bearer", BearerToken: "token"},
			{Name: "basic", BasicUsername: "user", BasicPassword: "pass"},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	candidates := registry.Candidates(inventory.AuthHints{
		RequiresAuth:          inventory.AuthRequirementYes,
		AuthContextCandidates: []string{"basic", "missing"},
	})
	if len(candidates) != 1 || candidates[0] != "basic" {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestCandidatesReturnAllWhenSchemeUnknown(t *testing.T) {
	registry, err := NewRegistry(config.Config{
		AuthContexts: []config.AuthContext{
			{Name: "bearer", BearerToken: "token"},
			{Name: "basic", BasicUsername: "user", BasicPassword: "pass"},
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry returned error: %v", err)
	}

	candidates := registry.Candidates(inventory.AuthHints{
		RequiresAuth: inventory.AuthRequirementYes,
		AuthSchemes:  []inventory.AuthScheme{inventory.AuthSchemeUnknown},
	})
	if len(candidates) != 2 {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}
