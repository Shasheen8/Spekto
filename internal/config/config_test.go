package config

import (
	"reflect"
	"testing"
	"time"
)

func TestLoadParsesConfigAndAppliesDefaults(t *testing.T) {
	data := []byte(`
targets:
  - name: rest-prod
    protocol: REST
    base_url: https://api.example.com
    discovery_modes: [spec, traffic]
auth_contexts:
  - name: prod-bearer
    bearer_token_env: TOGETHER_TOKEN
scan:
  request_budget: 500
output:
  json_path: out/inventory.json
`)

	cfg, err := Load(data)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(cfg.Targets))
	}
	if cfg.Targets[0].Protocol != "rest" {
		t.Fatalf("unexpected protocol: %s", cfg.Targets[0].Protocol)
	}
	if !reflect.DeepEqual(cfg.Targets[0].DiscoveryModes, []string{"spec", "traffic"}) {
		t.Fatalf("unexpected discovery modes: %#v", cfg.Targets[0].DiscoveryModes)
	}
	if cfg.Scan.Concurrency != 4 {
		t.Fatalf("expected default concurrency 4, got %d", cfg.Scan.Concurrency)
	}
	if cfg.Scan.Timeout != 5*time.Second {
		t.Fatalf("expected default timeout, got %s", cfg.Scan.Timeout)
	}
}

func TestApplyEnvOverridesScanAndOutput(t *testing.T) {
	cfg := Config{}
	cfg.applyDefaults()

	err := cfg.ApplyEnv(func(key string) string {
		values := map[string]string{
			"SPEKTO_SCAN_CONCURRENCY":        "8",
			"SPEKTO_SCAN_REQUEST_BUDGET":     "900",
			"SPEKTO_SCAN_TIMEOUT":            "12s",
			"SPEKTO_SCAN_RETRIES":            "2",
			"SPEKTO_SCAN_RATE_LIMIT":         "4.5",
			"SPEKTO_SCAN_MAX_RESPONSE_BYTES": "4096",
			"SPEKTO_SCAN_FOLLOW_REDIRECTS":   "true",
			"SPEKTO_OUTPUT_JSON":             "tmp/out.json",
		}
		return values[key]
	})
	if err != nil {
		t.Fatalf("ApplyEnv returned error: %v", err)
	}
	if cfg.Scan.Concurrency != 8 {
		t.Fatalf("unexpected concurrency: %d", cfg.Scan.Concurrency)
	}
	if cfg.Scan.RequestBudget != 900 {
		t.Fatalf("unexpected request budget: %d", cfg.Scan.RequestBudget)
	}
	if cfg.Scan.Timeout != 12*time.Second {
		t.Fatalf("unexpected timeout: %s", cfg.Scan.Timeout)
	}
	if cfg.Scan.Retries != 2 {
		t.Fatalf("unexpected retries: %d", cfg.Scan.Retries)
	}
	if cfg.Scan.RateLimit != 4.5 {
		t.Fatalf("unexpected rate limit: %v", cfg.Scan.RateLimit)
	}
	if cfg.Scan.MaxResponseBytes != 4096 {
		t.Fatalf("unexpected max response bytes: %d", cfg.Scan.MaxResponseBytes)
	}
	if !cfg.Scan.FollowRedirects {
		t.Fatalf("expected follow redirects to be true")
	}
	if cfg.Output.JSONPath != "tmp/out.json" {
		t.Fatalf("unexpected output path: %s", cfg.Output.JSONPath)
	}
}

func TestSelectTargetsReturnsEnabledTargetsByDefault(t *testing.T) {
	cfg := Config{
		Targets: []Target{
			{Name: "rest-a", Protocol: "rest", BaseURL: "https://a.example.com", Enabled: true},
			{Name: "rest-b", Protocol: "rest", BaseURL: "https://b.example.com"},
		},
	}

	selected, err := cfg.SelectTargets(nil)
	if err != nil {
		t.Fatalf("SelectTargets returned error: %v", err)
	}
	if len(selected) != 1 || selected[0].Name != "rest-a" {
		t.Fatalf("unexpected selected targets: %#v", selected)
	}
}

func TestSelectTargetsReturnsNamedTargets(t *testing.T) {
	cfg := Config{
		Targets: []Target{
			{Name: "rest-a", Protocol: "rest", BaseURL: "https://a.example.com"},
			{Name: "grpc-b", Protocol: "grpc", Endpoint: "grpc.example.com:443"},
		},
	}

	selected, err := cfg.SelectTargets([]string{"grpc-b"})
	if err != nil {
		t.Fatalf("SelectTargets returned error: %v", err)
	}
	if len(selected) != 1 || selected[0].Name != "grpc-b" {
		t.Fatalf("unexpected selected targets: %#v", selected)
	}
}

func TestSelectTargetsFilteredExcludesNamedTarget(t *testing.T) {
	cfg := Config{
		Targets: []Target{
			{Name: "rest-a", Protocol: "rest", BaseURL: "https://a.example.com"},
			{Name: "rest-b", Protocol: "rest", BaseURL: "https://b.example.com"},
		},
	}

	selected, err := cfg.SelectTargetsFiltered([]string{"rest-a", "rest-b"}, []string{"rest-b"})
	if err != nil {
		t.Fatalf("SelectTargetsFiltered returned error: %v", err)
	}
	if len(selected) != 1 || selected[0].Name != "rest-a" {
		t.Fatalf("unexpected selected targets: %#v", selected)
	}
}

func TestValidateRejectsUnsupportedProtocol(t *testing.T) {
	cfg := Config{
		Targets: []Target{
			{Name: "bad", Protocol: "soap", BaseURL: "https://api.example.com"},
		},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestValidateRejectsInvalidAuthConfiguration(t *testing.T) {
	cfg := Config{
		Targets: []Target{
			{Name: "grpc-a", Protocol: "grpc", Endpoint: "grpc.example.com:443"},
		},
		AuthContexts: []AuthContext{
			{
				Name:             "api",
				APIKeyHeaderName: "X-API-Key",
			},
		},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected validation error")
	}
}
