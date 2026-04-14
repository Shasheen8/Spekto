package config

import (
	"errors"
	"fmt"
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
	ResourceHints ResourceHints    `yaml:"resource_hints,omitempty"`
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
}

type OutputConfig struct {
	JSONPath      string `yaml:"json_path,omitempty"`
	SARIFPath     string `yaml:"sarif_path,omitempty"`
	EvidencePath  string `yaml:"evidence_path,omitempty"`
	CoveragePath  string `yaml:"coverage_path,omitempty"`
	SeedStorePath string `yaml:"seed_store_path,omitempty"`
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
	if err := yaml.Unmarshal(data, &cfg); err != nil {
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

	c.resolveAuthContextEnv(getenv)
	return nil
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
}

func (c *Config) resolveAuthContextEnv(getenv func(string) string) {
	for i := range c.AuthContexts {
		if env := strings.TrimSpace(c.AuthContexts[i].BearerTokenEnv); env != "" {
			c.AuthContexts[i].BearerToken = getenv(env)
		}
		if env := strings.TrimSpace(c.AuthContexts[i].BasicUsernameEnv); env != "" {
			c.AuthContexts[i].BasicUsername = getenv(env)
		}
		if env := strings.TrimSpace(c.AuthContexts[i].BasicPasswordEnv); env != "" {
			c.AuthContexts[i].BasicPassword = getenv(env)
		}
		if env := strings.TrimSpace(c.AuthContexts[i].APIKeyValueEnv); env != "" {
			c.AuthContexts[i].APIKeyValue = getenv(env)
		}
	}
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
