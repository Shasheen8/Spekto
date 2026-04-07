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
	Targets      []Target         `yaml:"targets"`
	Inventory    InventorySources `yaml:"inventory"`
	AuthContexts []AuthContext    `yaml:"auth_contexts"`
	Scan         ScanPolicy       `yaml:"scan"`
	Output       OutputConfig     `yaml:"output"`
}

type Target struct {
	Name           string   `yaml:"name"`
	Protocol       string   `yaml:"protocol"`
	BaseURL        string   `yaml:"base_url,omitempty"`
	Endpoint       string   `yaml:"endpoint,omitempty"`
	DiscoveryModes []string `yaml:"discovery_modes,omitempty"`
	Enabled        bool     `yaml:"enabled,omitempty"`
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
	Headers          map[string]string `yaml:"headers,omitempty"`
	BearerToken      string            `yaml:"bearer_token,omitempty"`
	BearerTokenEnv   string            `yaml:"bearer_token_env,omitempty"`
	BasicUsername    string            `yaml:"basic_username,omitempty"`
	BasicUsernameEnv string            `yaml:"basic_username_env,omitempty"`
	BasicPassword    string            `yaml:"basic_password,omitempty"`
	BasicPasswordEnv string            `yaml:"basic_password_env,omitempty"`
	Cookies          map[string]string `yaml:"cookies,omitempty"`
}

type ScanPolicy struct {
	EnabledRules  []string      `yaml:"enabled_rules,omitempty"`
	DisabledRules []string      `yaml:"disabled_rules,omitempty"`
	SafetyLevel   string        `yaml:"safety_level,omitempty"`
	RequestBudget int           `yaml:"request_budget,omitempty"`
	Concurrency   int           `yaml:"concurrency,omitempty"`
	Timeout       time.Duration `yaml:"timeout,omitempty"`
}

type OutputConfig struct {
	JSONPath     string `yaml:"json_path,omitempty"`
	SARIFPath    string `yaml:"sarif_path,omitempty"`
	EvidencePath string `yaml:"evidence_path,omitempty"`
	CoveragePath string `yaml:"coverage_path,omitempty"`
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

	c.resolveAuthContextEnv(getenv)
	return nil
}

func (c Config) SelectTargets(names []string) ([]Target, error) {
	if len(c.Targets) == 0 {
		return nil, nil
	}

	index := map[string]Target{}
	for _, target := range c.Targets {
		index[target.Name] = target
	}

	if len(names) > 0 {
		selected := make([]Target, 0, len(names))
		for _, name := range names {
			target, ok := index[name]
			if !ok {
				return nil, fmt.Errorf("unknown target %q", name)
			}
			selected = append(selected, target)
		}
		return selected, nil
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
	return selected, nil
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
	for i := range c.Targets {
		c.Targets[i].Protocol = strings.ToLower(strings.TrimSpace(c.Targets[i].Protocol))
		c.Targets[i].DiscoveryModes = normalizeStrings(c.Targets[i].DiscoveryModes)
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
