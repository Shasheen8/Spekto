package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var supportedProtocols = []string{"rest", "graphql", "grpc"}
var supportedDiscoveryModes = []string{"spec", "traffic", "manual", "active", "merge"}

type Config struct {
	Targets       []Target         `yaml:"targets"`
	Inventory     InventorySources `yaml:"inventory"`
	AuthContexts  []AuthContext    `yaml:"auth_contexts"`
	Scan          ScanPolicy       `yaml:"scan"`
	Output        OutputConfig     `yaml:"output"`
	PolicyPath    string           `yaml:"policy_path,omitempty"`
	ResourceHints ResourceHints    `yaml:"resource_hints,omitempty"`
	AI            AIConfig         `yaml:"ai,omitempty"`
}

// ResourceHints holds operator-provided seed values used by the candidate generator.
// PathParams and QueryParams are matched by exact parameter name.
// Constants act as a fallback pool matched across all parameter locations.
type ResourceHints struct {
	PathParams  map[string]string `yaml:"path_params,omitempty"`
	QueryParams map[string]string `yaml:"query_params,omitempty"`
	Constants   map[string]string `yaml:"constants,omitempty"`
}

type Target struct {
	Name           string   `yaml:"name"`
	Protocol       string   `yaml:"protocol"`
	BaseURL        string   `yaml:"base_url,omitempty"`
	Endpoint       string   `yaml:"endpoint,omitempty"`
	DiscoveryModes []string `yaml:"discovery_modes,omitempty"`
	AuthContexts   []string `yaml:"auth_contexts,omitempty"`
	Enabled        bool     `yaml:"enabled,omitempty"`
	AllowPlaintext bool     `yaml:"allow_plaintext,omitempty"`
}

type InventorySources struct {
	OpenAPI        []string `yaml:"openapi,omitempty"`
	GraphQLSchemas []string `yaml:"graphql_schemas,omitempty"`
	ProtoFiles     []string `yaml:"proto_files,omitempty"`
	ProtoImport    []string `yaml:"proto_import_paths,omitempty"`
	DescriptorSets []string `yaml:"descriptor_sets,omitempty"`
	GRPCReflection []string `yaml:"grpc_reflection,omitempty"`
	HAR            []string `yaml:"har,omitempty"`
	Postman        []string `yaml:"postman,omitempty"`
	AccessLogs     []string `yaml:"access_logs,omitempty"`
	ManualSeeds    []string `yaml:"manual_seeds,omitempty"`
}

type AuthContext struct {
	Name             string            `yaml:"name"`
	Roles            []string          `yaml:"roles,omitempty"`
	Headers          map[string]string `yaml:"headers,omitempty"`
	BearerToken      string            `yaml:"bearer_token,omitempty"`
	BearerTokenEnv   string            `yaml:"bearer_token_env,omitempty"`
	BasicUsername    string            `yaml:"basic_username,omitempty"`
	BasicUsernameEnv string            `yaml:"basic_username_env,omitempty"`
	BasicPassword    string            `yaml:"basic_password,omitempty"`
	BasicPasswordEnv string            `yaml:"basic_password_env,omitempty"`
	APIKeyHeaderName string            `yaml:"api_key_header_name,omitempty"`
	APIKeyQueryName  string            `yaml:"api_key_query_name,omitempty"`
	APIKeyValue      string            `yaml:"api_key_value,omitempty"`
	APIKeyValueEnv   string            `yaml:"api_key_value_env,omitempty"`
	Cookies          map[string]string `yaml:"cookies,omitempty"`
	MTLS             *MTLSConfig       `yaml:"mtls,omitempty"`
	Login            *LoginFlow        `yaml:"login,omitempty"`
}

type ScanPolicy struct {
	EnabledRules     []string      `yaml:"enabled_rules,omitempty"`
	DisabledRules    []string      `yaml:"disabled_rules,omitempty"`
	SafetyLevel      string        `yaml:"safety_level,omitempty"`
	RequestBudget    int           `yaml:"request_budget,omitempty"`
	Concurrency      int           `yaml:"concurrency,omitempty"`
	Timeout          time.Duration `yaml:"timeout,omitempty"`
	Retries          int           `yaml:"retries,omitempty"`
	RateLimit        float64       `yaml:"rate_limit,omitempty"`
	MaxResponseBytes int64         `yaml:"max_response_bytes,omitempty"`
	FollowRedirects  bool          `yaml:"follow_redirects,omitempty"`
	BodyCapture      string        `yaml:"body_capture,omitempty"`
	AllowWrite       bool          `yaml:"allow_write,omitempty"`
	AllowUnsafeRules bool          `yaml:"allow_unsafe_rules,omitempty"`
	AllowLiveSSRF    bool          `yaml:"allow_live_ssrf,omitempty"`
	// TargetAllowlist restricts scanning to targets whose hostname matches an
	// entry in the list. Supports exact hostnames and wildcard prefixes (*.example.com).
	// When empty, all configured targets are permitted.
	TargetAllowlist []string `yaml:"target_allowlist,omitempty"`
}

type OutputConfig struct {
	JSONPath      string `yaml:"json_path,omitempty"`
	SARIFPath     string `yaml:"sarif_path,omitempty"`
	EvidencePath  string `yaml:"evidence_path,omitempty"`
	CoveragePath  string `yaml:"coverage_path,omitempty"`
	SeedStorePath string `yaml:"seed_store_path,omitempty"`
	FindingsPath  string `yaml:"findings_path,omitempty"`
}

type AIConfig struct {
	Enabled        bool          `yaml:"enabled,omitempty"`
	Provider       string        `yaml:"provider,omitempty"`
	Model          string        `yaml:"model,omitempty"`
	MaxFindings    int           `yaml:"max_findings,omitempty"`
	Timeout        time.Duration `yaml:"timeout,omitempty"`
	InputBodyLimit int           `yaml:"input_body_limit,omitempty"`
	OutputPath     string        `yaml:"output_path,omitempty"`
	APIKeyEnv      string        `yaml:"api_key_env,omitempty"`
}

type MTLSConfig struct {
	CertFile           string `yaml:"cert_file,omitempty"`
	KeyFile            string `yaml:"key_file,omitempty"`
	CAFile             string `yaml:"ca_file,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
}

type LoginFlow struct {
	Method      string            `yaml:"method,omitempty"`
	URL         string            `yaml:"url,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	Body        string            `yaml:"body,omitempty"`
	ContentType string            `yaml:"content_type,omitempty"`
	Capture     LoginCapture      `yaml:"capture,omitempty"`
}

type LoginCapture struct {
	BearerJSONPointer string `yaml:"bearer_json_pointer,omitempty"`
	Header            string `yaml:"header,omitempty"`
	Cookie            string `yaml:"cookie,omitempty"`
}

func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	return Load(data)
}

func Load(data []byte) (Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	cfg.applyDefaults()
	if err := cfg.ApplyEnv(os.Getenv); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) ApplyEnv(getenv func(string) string) error {
	if getenv == nil {
		return nil
	}

	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_CONCURRENCY")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_CONCURRENCY: %w", err)
		}
		c.Scan.Concurrency = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_REQUEST_BUDGET")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_REQUEST_BUDGET: %w", err)
		}
		c.Scan.RequestBudget = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_TIMEOUT")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_TIMEOUT: %w", err)
		}
		c.Scan.Timeout = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_RETRIES")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_RETRIES: %w", err)
		}
		c.Scan.Retries = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_RATE_LIMIT")); raw != "" {
		value, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_RATE_LIMIT: %w", err)
		}
		c.Scan.RateLimit = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_MAX_RESPONSE_BYTES")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_MAX_RESPONSE_BYTES: %w", err)
		}
		c.Scan.MaxResponseBytes = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_FOLLOW_REDIRECTS")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_FOLLOW_REDIRECTS: %w", err)
		}
		c.Scan.FollowRedirects = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_SAFETY_LEVEL")); raw != "" {
		c.Scan.SafetyLevel = strings.ToLower(raw)
		applySafetyLevel(&c.Scan)
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_BODY_CAPTURE")); raw != "" {
		c.Scan.BodyCapture = strings.ToLower(raw)
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_ALLOW_WRITE")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_ALLOW_WRITE: %w", err)
		}
		c.Scan.AllowWrite = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_ALLOW_UNSAFE_RULES")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_ALLOW_UNSAFE_RULES: %w", err)
		}
		c.Scan.AllowUnsafeRules = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_SCAN_ALLOW_LIVE_SSRF")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_SCAN_ALLOW_LIVE_SSRF: %w", err)
		}
		c.Scan.AllowLiveSSRF = value
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_OUTPUT_JSON")); raw != "" {
		c.Output.JSONPath = raw
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_OUTPUT_SARIF")); raw != "" {
		c.Output.SARIFPath = raw
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_OUTPUT_EVIDENCE")); raw != "" {
		c.Output.EvidencePath = raw
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_OUTPUT_COVERAGE")); raw != "" {
		c.Output.CoveragePath = raw
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_OUTPUT_SEED_STORE")); raw != "" {
		c.Output.SeedStorePath = raw
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_OUTPUT_FINDINGS")); raw != "" {
		c.Output.FindingsPath = raw
	}

	if raw := strings.TrimSpace(getenv("SPEKTO_AI_ENABLED")); raw != "" {
		val, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_AI_ENABLED: %w", err)
		}
		c.AI.Enabled = val
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_AI_MODEL")); raw != "" {
		c.AI.Model = raw
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_AI_MAX_FINDINGS")); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_AI_MAX_FINDINGS: %w", err)
		}
		c.AI.MaxFindings = val
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_AI_TIMEOUT")); raw != "" {
		val, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_AI_TIMEOUT: %w", err)
		}
		c.AI.Timeout = val
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_AI_INPUT_BODY_LIMIT")); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("parse SPEKTO_AI_INPUT_BODY_LIMIT: %w", err)
		}
		c.AI.InputBodyLimit = val
	}
	if raw := strings.TrimSpace(getenv("SPEKTO_AI_OUTPUT_PATH")); raw != "" {
		c.AI.OutputPath = raw
	}

	return c.resolveAuthContextEnv(getenv)
}

func (c Config) SelectTargets(names []string) ([]Target, error) {
	return c.SelectTargetsFiltered(names, nil)
}

func (c Config) SelectTargetsFiltered(include []string, exclude []string) ([]Target, error) {
	if len(c.Targets) == 0 {
		return nil, nil
	}

	index := map[string]Target{}
	for _, target := range c.Targets {
		index[target.Name] = target
	}

	if len(include) > 0 {
		selected := make([]Target, 0, len(include))
		for _, name := range include {
			target, ok := index[name]
			if !ok {
				return nil, fmt.Errorf("unknown target %q", name)
			}
			selected = append(selected, target)
		}
		return excludeTargets(selected, exclude), nil
	}

	selected := make([]Target, 0, len(c.Targets))
	enabledCount := 0
	for _, target := range c.Targets {
		if target.Enabled {
			enabledCount++
		}
	}
	for _, target := range c.Targets {
		if enabledCount == 0 || target.Enabled {
			selected = append(selected, target)
		}
	}
	return excludeTargets(selected, exclude), nil
}

func (c Config) Validate() error {
	targetNames := map[string]struct{}{}
	for _, target := range c.Targets {
		if strings.TrimSpace(target.Name) == "" {
			return errors.New("target name must not be empty")
		}
		if _, exists := targetNames[target.Name]; exists {
			return fmt.Errorf("duplicate target %q", target.Name)
		}
		targetNames[target.Name] = struct{}{}
		if !slices.Contains(supportedProtocols, target.Protocol) {
			return fmt.Errorf("target %q has unsupported protocol %q", target.Name, target.Protocol)
		}
		if strings.TrimSpace(target.BaseURL) == "" && strings.TrimSpace(target.Endpoint) == "" {
			return fmt.Errorf("target %q must include base_url or endpoint", target.Name)
		}
		if target.Protocol == "grpc" && strings.TrimSpace(target.Endpoint) == "" {
			return fmt.Errorf("grpc target %q must include endpoint", target.Name)
		}
		for _, mode := range target.DiscoveryModes {
			if !slices.Contains(supportedDiscoveryModes, mode) {
				return fmt.Errorf("target %q has unsupported discovery mode %q", target.Name, mode)
			}
		}
		if err := validatePlaintextTarget(target, c.AuthContexts); err != nil {
			return err
		}
	}

	authNames := map[string]struct{}{}
	for _, auth := range c.AuthContexts {
		if strings.TrimSpace(auth.Name) == "" {
			return errors.New("auth context name must not be empty")
		}
		if _, exists := authNames[auth.Name]; exists {
			return fmt.Errorf("duplicate auth context %q", auth.Name)
		}
		authNames[auth.Name] = struct{}{}
		if auth.APIKeyHeaderName != "" && strings.TrimSpace(auth.APIKeyValue) == "" && strings.TrimSpace(auth.APIKeyValueEnv) == "" {
			return fmt.Errorf("auth context %q api key header requires a value", auth.Name)
		}
		if auth.APIKeyQueryName != "" && strings.TrimSpace(auth.APIKeyValue) == "" && strings.TrimSpace(auth.APIKeyValueEnv) == "" {
			return fmt.Errorf("auth context %q api key query requires a value", auth.Name)
		}
		if auth.MTLS != nil {
			if strings.TrimSpace(auth.MTLS.CertFile) == "" || strings.TrimSpace(auth.MTLS.KeyFile) == "" {
				return fmt.Errorf("auth context %q mtls requires cert_file and key_file", auth.Name)
			}
		}
		if auth.Login != nil {
			if strings.TrimSpace(auth.Login.URL) == "" {
				return fmt.Errorf("auth context %q login requires url", auth.Name)
			}
			if auth.Login.Capture.BearerJSONPointer == "" && auth.Login.Capture.Header == "" && auth.Login.Capture.Cookie == "" {
				return fmt.Errorf("auth context %q login requires a capture target", auth.Name)
			}
		}
	}

	if c.Scan.Concurrency <= 0 {
		return errors.New("scan concurrency must be greater than zero")
	}
	if c.Scan.RequestBudget <= 0 {
		return errors.New("scan request_budget must be greater than zero")
	}
	if c.Scan.Timeout <= 0 {
		return errors.New("scan timeout must be greater than zero")
	}
	if c.Scan.Retries < 0 {
		return errors.New("scan retries must not be negative")
	}
	if c.Scan.RateLimit < 0 {
		return errors.New("scan rate_limit must not be negative")
	}
	if c.Scan.MaxResponseBytes < 0 {
		return errors.New("scan max_response_bytes must not be negative")
	}
	switch c.Scan.SafetyLevel {
	case "read_only", "write", "unsafe":
	default:
		return fmt.Errorf("unsupported scan safety_level %q", c.Scan.SafetyLevel)
	}
	switch c.Scan.BodyCapture {
	case "redacted", "full":
	default:
		return fmt.Errorf("unsupported scan body_capture %q", c.Scan.BodyCapture)
	}

	return nil
}

func (c *Config) applyDefaults() {
	if c.Scan.Concurrency == 0 {
		c.Scan.Concurrency = 4
	}
	if c.Scan.RequestBudget == 0 {
		c.Scan.RequestBudget = 200
	}
	if c.Scan.Timeout == 0 {
		c.Scan.Timeout = 5 * time.Second
	}
	if c.Scan.MaxResponseBytes == 0 {
		c.Scan.MaxResponseBytes = 64 * 1024
	}
	c.Scan.SafetyLevel = strings.ToLower(strings.TrimSpace(c.Scan.SafetyLevel))
	if c.Scan.SafetyLevel == "" {
		c.Scan.SafetyLevel = "read_only"
	}
	c.Scan.BodyCapture = strings.ToLower(strings.TrimSpace(c.Scan.BodyCapture))
	if c.Scan.BodyCapture == "" {
		c.Scan.BodyCapture = "redacted"
	}
	applySafetyLevel(&c.Scan)
	for i := range c.Targets {
		c.Targets[i].Protocol = strings.ToLower(strings.TrimSpace(c.Targets[i].Protocol))
		c.Targets[i].DiscoveryModes = normalizeStrings(c.Targets[i].DiscoveryModes)
		c.Targets[i].AuthContexts = normalizeNames(c.Targets[i].AuthContexts)
	}
	for i := range c.AuthContexts {
		c.AuthContexts[i].Roles = normalizeNames(c.AuthContexts[i].Roles)
		if c.AuthContexts[i].Login != nil {
			c.AuthContexts[i].Login.Method = strings.ToUpper(strings.TrimSpace(c.AuthContexts[i].Login.Method))
			if c.AuthContexts[i].Login.Method == "" {
				c.AuthContexts[i].Login.Method = httpMethodPost
			}
		}
	}
	if c.AI.MaxFindings == 0 {
		c.AI.MaxFindings = 50
	}
	if c.AI.Timeout == 0 {
		c.AI.Timeout = 2 * time.Minute
	}
	if c.AI.InputBodyLimit == 0 {
		c.AI.InputBodyLimit = 500
	}
	if c.AI.APIKeyEnv == "" {
		c.AI.APIKeyEnv = "TOGETHER_API_KEY"
	}
	if c.AI.Model == "" {
		c.AI.Model = "Qwen/Qwen3-Coder-Next-FP8"
	}
}

func applySafetyLevel(scan *ScanPolicy) {
	switch scan.SafetyLevel {
	case "write":
		scan.AllowWrite = true
	case "unsafe":
		scan.AllowWrite = true
		scan.AllowUnsafeRules = true
		scan.AllowLiveSSRF = true
	}
}

func (c *Config) resolveAuthContextEnv(getenv func(string) string) error {
	for i := range c.AuthContexts {
		if env := strings.TrimSpace(c.AuthContexts[i].BearerTokenEnv); env != "" {
			value := strings.TrimSpace(getenv(env))
			if value == "" {
				return fmt.Errorf("auth context %q bearer_token_env %q is not set", c.AuthContexts[i].Name, env)
			}
			c.AuthContexts[i].BearerToken = value
		}
		if env := strings.TrimSpace(c.AuthContexts[i].BasicUsernameEnv); env != "" {
			value := strings.TrimSpace(getenv(env))
			if value == "" {
				return fmt.Errorf("auth context %q basic_username_env %q is not set", c.AuthContexts[i].Name, env)
			}
			c.AuthContexts[i].BasicUsername = value
		}
		if env := strings.TrimSpace(c.AuthContexts[i].BasicPasswordEnv); env != "" {
			value := strings.TrimSpace(getenv(env))
			if value == "" {
				return fmt.Errorf("auth context %q basic_password_env %q is not set", c.AuthContexts[i].Name, env)
			}
			c.AuthContexts[i].BasicPassword = value
		}
		if env := strings.TrimSpace(c.AuthContexts[i].APIKeyValueEnv); env != "" {
			value := strings.TrimSpace(getenv(env))
			if value == "" {
				return fmt.Errorf("auth context %q api_key_value_env %q is not set", c.AuthContexts[i].Name, env)
			}
			c.AuthContexts[i].APIKeyValue = value
		}
	}
	return nil
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func normalizeNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func excludeTargets(targets []Target, exclude []string) []Target {
	if len(exclude) == 0 {
		return targets
	}
	ignored := map[string]struct{}{}
	for _, name := range exclude {
		trimmed := strings.TrimSpace(name)
		if trimmed != "" {
			ignored[trimmed] = struct{}{}
		}
	}
	selected := make([]Target, 0, len(targets))
	for _, target := range targets {
		if _, skip := ignored[target.Name]; skip {
			continue
		}
		selected = append(selected, target)
	}
	return selected
}

const httpMethodPost = "POST"

func validatePlaintextTarget(target Target, authContexts []AuthContext) error {
	if target.AllowPlaintext || target.Protocol == "grpc" {
		return nil
	}
	rawURL := strings.TrimSpace(target.BaseURL)
	if rawURL == "" {
		rawURL = strings.TrimSpace(target.Endpoint)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("target %q has invalid url %q", target.Name, rawURL)
	}
	if parsed.Scheme != "http" {
		return nil
	}
	if isLoopbackHost(parsed.Hostname()) {
		return nil
	}
	if len(target.AuthContexts) > 0 || len(authContexts) > 0 {
		return fmt.Errorf("target %q uses plaintext HTTP with auth; set allow_plaintext only for approved non-production targets", target.Name)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
