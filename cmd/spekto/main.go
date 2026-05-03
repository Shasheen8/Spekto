package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	activediscovery "github.com/Shasheen8/Spekto/internal/discovery/active"
	"github.com/Shasheen8/Spekto/internal/enrichment"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	policyeval "github.com/Shasheen8/Spekto/internal/policy"
	graphqldiscovery "github.com/Shasheen8/Spekto/internal/protocol/graphql"
	grpcdiscovery "github.com/Shasheen8/Spekto/internal/protocol/grpc"
	restdiscovery "github.com/Shasheen8/Spekto/internal/protocol/rest"
	"github.com/Shasheen8/Spekto/internal/report"
	"github.com/Shasheen8/Spekto/internal/rules"
	schemavalidation "github.com/Shasheen8/Spekto/internal/schema"
	"github.com/Shasheen8/Spekto/internal/seed"
)

var version = "dev"

const defaultScanOutDir = "spekto-artifacts"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	if isHelpArg(args[0]) || args[0] == "help" {
		printRootHelp(os.Stdout)
		return nil
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(os.Stdout, version)
		return nil
	case "discover":
		if len(args) < 2 {
			return fmt.Errorf("unsupported discover subcommand; run spekto discover --help")
		}
		if isHelpArg(args[1]) || args[1] == "help" {
			printDiscoverHelp(os.Stdout)
			return nil
		}
		switch args[1] {
		case "spec":
			return runDiscoverSpec(args[2:])
		case "traffic":
			return runDiscoverTraffic(args[2:])
		case "manual":
			return runDiscoverManual(args[2:])
		case "active":
			return runDiscoverActive(args[2:])
		case "merge":
			return runDiscoverMerge(args[2:])
		default:
			return fmt.Errorf("unsupported discover subcommand %q; run spekto discover --help", args[1])
		}
	case "scan":
		return runScan(args[1:])
	default:
		return fmt.Errorf("unsupported command %q; run spekto --help", args[0])
	}
}

func runDiscoverSpec(args []string) error {
	if wantsHelp(args) {
		printDiscoverSpecHelp(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("discover spec", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var openapiPaths multiValue
	var graphqlPaths multiValue
	var protoFiles multiValue
	var protoImportPaths multiValue
	var descriptorSets multiValue
	var grpcReflectionTargets multiValue
	var outPath string
	var allowEmpty bool

	fs.Var(&openapiPaths, "openapi", "OpenAPI or Swagger file path")
	fs.Var(&graphqlPaths, "graphql-schema", "GraphQL SDL or introspection JSON file path")
	fs.Var(&protoFiles, "proto", "Proto file path")
	fs.Var(&protoImportPaths, "proto-import-path", "Proto import path")
	fs.Var(&descriptorSets, "descriptor-set", "Protobuf descriptor set file path")
	fs.Var(&grpcReflectionTargets, "grpc-reflection", "gRPC reflection target host:port")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")
	fs.BoolVar(&allowEmpty, "allow-empty", false, "Allow writing an inventory with zero operations")

	if err := fs.Parse(args); err != nil {
		return err
	}

	merged, err := buildSpecInventory(openapiPaths, graphqlPaths, protoFiles, protoImportPaths, descriptorSets, grpcReflectionTargets)
	if err != nil {
		return err
	}
	if merged.Summary.Total == 0 && !allowEmpty {
		return fmt.Errorf("discovery produced zero operations; pass --allow-empty to write an empty inventory")
	}
	return writeInventory(outPath, merged)
}

func buildSpecInventory(openapiPaths, graphqlPaths, protoFiles, protoImportPaths, descriptorSets, grpcReflectionTargets []string) (inventory.Inventory, error) {
	if len(openapiPaths) == 0 && len(graphqlPaths) == 0 && len(protoFiles) == 0 && len(descriptorSets) == 0 && len(grpcReflectionTargets) == 0 {
		return inventory.Inventory{}, fmt.Errorf("spec discovery requires at least one input source")
	}

	var operationSets [][]inventory.Operation

	for _, path := range openapiPaths {
		if err := checkInputFileSize(path); err != nil {
			return inventory.Inventory{}, err
		}
		doc, err := restdiscovery.ParseFile(context.Background(), path)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("openapi %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	for _, path := range graphqlPaths {
		data, err := readBoundedFile(path)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("graphql schema %s: %w", path, err)
		}
		doc, err := graphqldiscovery.ParseData(data, path)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("graphql schema %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	for _, path := range descriptorSets {
		doc, err := grpcdiscovery.ParseDescriptorSetFile(path)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("descriptor set %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}
	for _, target := range grpcReflectionTargets {
		doc, err := grpcdiscovery.ParseReflectionTarget(context.Background(), target)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("grpc reflection %s: %w", target, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	if len(protoFiles) > 0 {
		normalizedFiles := make([]string, 0, len(protoFiles))
		for _, file := range protoFiles {
			normalizedFiles = append(normalizedFiles, filepath.Clean(file))
		}
		doc, err := grpcdiscovery.ParseProtoFiles(protoImportPaths, normalizedFiles)
		if err != nil {
			return inventory.Inventory{}, fmt.Errorf("proto files: %w", err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	return inventory.Merge(operationSets...), nil
}

func runDiscoverTraffic(args []string) error {
	if wantsHelp(args) {
		printDiscoverTrafficHelp(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("discover traffic", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var harPaths multiValue
	var postmanPaths multiValue
	var accessLogPaths multiValue
	var outPath string
	var allowEmpty bool

	fs.Var(&harPaths, "har", "HAR file path")
	fs.Var(&postmanPaths, "postman", "Postman collection file path")
	fs.Var(&accessLogPaths, "access-log", "Access log extract file path")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")
	fs.BoolVar(&allowEmpty, "allow-empty", false, "Allow writing an inventory with zero operations")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(harPaths) == 0 && len(postmanPaths) == 0 && len(accessLogPaths) == 0 {
		return fmt.Errorf("discover traffic requires at least one traffic input source")
	}

	var operationSets [][]inventory.Operation
	for _, path := range harPaths {
		data, err := readBoundedFile(path)
		if err != nil {
			return fmt.Errorf("har %s: %w", path, err)
		}
		doc, err := inventory.ParseHAR(data, path)
		if err != nil {
			return fmt.Errorf("har %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}
	for _, path := range postmanPaths {
		data, err := readBoundedFile(path)
		if err != nil {
			return fmt.Errorf("postman %s: %w", path, err)
		}
		doc, err := inventory.ParsePostman(data, path)
		if err != nil {
			return fmt.Errorf("postman %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}
	for _, path := range accessLogPaths {
		doc, err := inventory.ParseAccessLogFile(path)
		if err != nil {
			return fmt.Errorf("access log %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	return writeMergedInventory(outPath, allowEmpty, operationSets...)
}

func runDiscoverManual(args []string) error {
	if wantsHelp(args) {
		printDiscoverManualHelp(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("discover manual", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var seedPaths multiValue
	var outPath string
	var allowEmpty bool

	fs.Var(&seedPaths, "seed", "Manual YAML or JSON seed file path")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")
	fs.BoolVar(&allowEmpty, "allow-empty", false, "Allow writing an inventory with zero operations")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(seedPaths) == 0 {
		return fmt.Errorf("discover manual requires at least one seed input")
	}

	var operationSets [][]inventory.Operation
	for _, path := range seedPaths {
		data, err := readBoundedFile(path)
		if err != nil {
			return fmt.Errorf("seed %s: %w", path, err)
		}
		doc, err := inventory.ParseManual(data, path)
		if err != nil {
			return fmt.Errorf("seed %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	return writeMergedInventory(outPath, allowEmpty, operationSets...)
}

func runDiscoverActive(args []string) error {
	if wantsHelp(args) {
		printDiscoverActiveHelp(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("discover active", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var baseURLs multiValue
	var grpcReflectionTargets multiValue
	var outPath string
	var allowEmpty bool

	fs.Var(&baseURLs, "base-url", "Base URL to probe for spec and GraphQL endpoints")
	fs.Var(&grpcReflectionTargets, "grpc-reflection", "gRPC reflection target host:port")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")
	fs.BoolVar(&allowEmpty, "allow-empty", false, "Allow writing an inventory with zero operations")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(baseURLs) == 0 && len(grpcReflectionTargets) == 0 {
		return fmt.Errorf("discover active requires at least one active target")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var operationSets [][]inventory.Operation
	for _, baseURL := range baseURLs {
		doc, err := activediscovery.DiscoverHTTPTarget(context.Background(), client, baseURL)
		if err != nil {
			return fmt.Errorf("active base-url %s: %w", baseURL, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}
	for _, target := range grpcReflectionTargets {
		doc, err := grpcdiscovery.ParseReflectionTarget(context.Background(), target)
		if err != nil {
			return fmt.Errorf("active grpc reflection %s: %w", target, err)
		}
		operationSets = append(operationSets, markGRPCReflectionActive(doc.Operations, target))
	}

	return writeMergedInventory(outPath, allowEmpty, operationSets...)
}

func runDiscoverMerge(args []string) error {
	if wantsHelp(args) {
		printDiscoverMergeHelp(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("discover merge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var inventoryPaths multiValue
	var outPath string

	fs.Var(&inventoryPaths, "inventory", "Canonical inventory JSON file path")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(inventoryPaths) == 0 {
		return fmt.Errorf("discover merge requires at least one inventory input")
	}

	inventories := make([]inventory.Inventory, 0, len(inventoryPaths))
	for _, path := range inventoryPaths {
		inv, err := inventory.LoadInventoryFile(path)
		if err != nil {
			return fmt.Errorf("inventory %s: %w", path, err)
		}
		inventories = append(inventories, inv)
	}

	merged := inventory.MergeInventories(inventories...)
	data, err := merged.JSON()
	if err != nil {
		return err
	}
	if outPath == "" {
		if _, err = os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
		report.PrintDiscoverySummary(os.Stderr, merged, "stdout")
		return nil
	}
	if err := writeFile(outPath, append(data, '\n')); err != nil {
		return err
	}
	report.PrintDiscoverySummary(os.Stderr, merged, outPath)
	return nil
}

func writeMergedInventory(outPath string, allowEmpty bool, operationSets ...[]inventory.Operation) error {
	merged := inventory.Merge(operationSets...)
	if merged.Summary.Total == 0 && !allowEmpty {
		return fmt.Errorf("discovery produced zero operations; pass --allow-empty to write an empty inventory")
	}
	return writeInventory(outPath, merged)
}

func writeInventory(outPath string, merged inventory.Inventory) error {
	data, err := merged.JSON()
	if err != nil {
		return err
	}

	if outPath == "" {
		if _, err = os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
		report.PrintDiscoverySummary(os.Stderr, merged, "stdout")
		return nil
	}

	if err := writeFile(outPath, append(data, '\n')); err != nil {
		return err
	}
	report.PrintDiscoverySummary(os.Stderr, merged, outPath)
	return nil
}

func usageError() error {
	return fmt.Errorf("usage: spekto --help")
}

func isHelpArg(arg string) bool {
	return arg == "--help" || arg == "-h"
}

func wantsHelp(args []string) bool {
	return len(args) > 0 && (isHelpArg(args[0]) || args[0] == "help")
}

func printRootHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto <command> [flags]

Common workflows:
  spekto scan --config spekto.yaml --openapi openapi.yaml --out-dir spekto-artifacts
  spekto discover spec --openapi openapi.yaml --out inventory.json
  spekto version

Commands:
  scan       Execute bounded API probes and write evidence/findings artifacts
  discover   Build canonical API inventory from specs, traffic, manual seeds, or active discovery
  version    Print Spekto version

Run "spekto <command> --help" for command flags.`)
}

func printDiscoverHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto discover <subcommand> [flags]

Subcommands:
  spec      Read OpenAPI, GraphQL, proto, descriptors, or gRPC reflection
  traffic   Read HAR, Postman collections, or access logs
  manual    Read operator-authored seed files
  active    Actively discover bounded HTTP and gRPC inventory
  merge     Merge inventory JSON files

Example:
  spekto discover spec --openapi openapi.yaml --out inventory.json`)
}

func printScanHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto scan --config spekto.yaml (--inventory inventory.json | --openapi openapi.yaml) [flags]

Inputs:
  --config file              Scan configuration
  --inventory file           Existing canonical inventory
  --openapi file             OpenAPI or Swagger input
  --graphql-schema file      GraphQL schema input
  --proto file               Protobuf source input
  --descriptor-set file      Protobuf descriptor set
  --grpc-reflection target   gRPC reflection host:port
  --policy file              Authorization and custom-check policy YAML

Scope:
  --target name              Include target
  --exclude-target name      Exclude target
  --auth-context name        Include auth context
  --operation value          Include operation ID or locator substring
  --tag value                Include operation tag

Safety:
  --dry-run                  Print scan plan without sending requests
  --no-rules                 Skip rule-based checks after seeding
  --stateful                 Enable BOLA/BFLA cross-context checks
  --allow-write              Allow mutating seed requests
  --allow-write-stateful     Include mutating stateful authorization checks
  --allow-unsafe-rules       Allow destructive/resource-heavy probes
  --allow-live-ssrf          Allow live metadata SSRF probes

Runtime:
  --concurrency n            Override scan concurrency
  --request-budget n         Override request budget
  --timeout duration         Override request timeout
  --follow-redirects bool    Follow redirects

Artifacts:
  --out-dir dir              Directory for inventory/evidence/coverage/findings/SARIF
  --out file                 Evidence bundle path
  --coverage-out file        Coverage JSON path
  --findings-out file        Findings JSON path
  --sarif-out file           SARIF path
  --seed-store file          Successful seed store path

AI Enrichment:
  --ai-enrich                Enrich findings with AI-generated analysis
  --ai-model model           Override AI model for enrichment
  --ai-max-findings n        Max findings to send for AI enrichment
  --ai-out file              Output path for enriched findings JSON`)
}

func printDiscoverSpecHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto discover spec [--openapi file] [--graphql-schema file] [--proto file] [--descriptor-set file] [--grpc-reflection host:port] [--out inventory.json]

Reads API specifications and writes canonical inventory JSON.`)
}

func printDiscoverTrafficHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto discover traffic [--har file] [--postman file] [--access-log file] [--out inventory.json]

Reads captured traffic artifacts and writes canonical inventory JSON.`)
}

func printDiscoverManualHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto discover manual --seed file [--out inventory.json]

Reads operator-authored seed files and writes canonical inventory JSON.`)
}

func printDiscoverActiveHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto discover active [--base-url url] [--grpc-reflection host:port] [--out inventory.json]

Runs bounded active discovery against allowed targets.`)
}

func printDiscoverMergeHelp(w io.Writer) {
	fmt.Fprintln(w, `Usage: spekto discover merge --inventory file [--inventory file...] [--out inventory.json]

Merges multiple canonical inventory JSON files.`)
}

type multiValue []string

func (m *multiValue) String() string {
	return strings.Join(*m, ",")
}

func (m *multiValue) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("value must not be empty")
	}
	*m = append(*m, value)
	return nil
}

func markGRPCReflectionActive(ops []inventory.Operation, target string) []inventory.Operation {
	out := make([]inventory.Operation, 0, len(ops))
	for _, op := range ops {
		op.SourceRefs = []inventory.SourceRef{{
			Type:         inventory.SourceActive,
			Location:     target,
			ParserFamily: "grpc_reflection",
			SupportLevel: inventory.SupportLevelFull,
		}}
		op.Provenance.ActivelyDiscovered = true
		if op.Confidence < 0.8 {
			op.Confidence = 0.8
		}
		out = append(out, op)
	}
	return out
}

func runScan(args []string) error {
	if wantsHelp(args) {
		printScanHelp(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var configPath string
	var inventoryPath string
	var outDir string
	var outPath string
	var findingsPath string
	var sarifPath string
	var coveragePath string
	var seedStorePath string
	var policyPath string
	var openapiPaths multiValue
	var graphqlPaths multiValue
	var protoFiles multiValue
	var protoImportPaths multiValue
	var descriptorSets multiValue
	var grpcReflectionTargets multiValue
	var noRules bool
	var dryRun bool
	var stateful bool
	var allowWriteStateful bool
	var allowWrite bool
	var allowUnsafeRules bool
	var allowLiveSSRF bool
	var includeTargets multiValue
	var excludeTargets multiValue
	var authContexts multiValue
	var includeOperations multiValue
	var includeTags multiValue
	var concurrency int
	var requestBudget int
	var timeout time.Duration
	var bodyCapture string
	var followRedirects triStateBool
	var aiEnrich bool
	var aiModel string
	var aiMaxFindings int
	var aiOut string

	fs.StringVar(&configPath, "config", "", "Config file path")
	fs.StringVar(&inventoryPath, "inventory", "", "Canonical inventory JSON file path")
	fs.Var(&openapiPaths, "openapi", "OpenAPI or Swagger file path")
	fs.Var(&graphqlPaths, "graphql-schema", "GraphQL SDL or introspection JSON file path")
	fs.Var(&protoFiles, "proto", "Proto file path")
	fs.Var(&protoImportPaths, "proto-import-path", "Proto import path")
	fs.Var(&descriptorSets, "descriptor-set", "Protobuf descriptor set file path")
	fs.Var(&grpcReflectionTargets, "grpc-reflection", "gRPC reflection target host:port")
	fs.StringVar(&outDir, "out-dir", "", "Output directory for default scan artifacts")
	fs.StringVar(&outPath, "out", "", "Output path for evidence bundle JSON")
	fs.StringVar(&findingsPath, "findings-out", "", "Output path for findings JSON")
	fs.StringVar(&sarifPath, "sarif-out", "", "Output path for SARIF findings (for GitHub Advanced Security)")
	fs.StringVar(&coveragePath, "coverage-out", "", "Output path for coverage summary JSON")
	fs.StringVar(&seedStorePath, "seed-store", "", "Path to seed store JSON file (captures successful requests)")
	fs.StringVar(&policyPath, "policy", "", "Authorization and custom-check policy YAML path")
	fs.BoolVar(&noRules, "no-rules", false, "Skip rule-based scanning after seeding")
	fs.BoolVar(&dryRun, "dry-run", false, "Print what would be scanned without sending any requests")
	fs.BoolVar(&stateful, "stateful", false, "Enable stateful authorization checks (BOLA001, BFLA001); requires at least two auth contexts")
	fs.BoolVar(&allowWriteStateful, "allow-write-stateful", false, "Include mutating methods (POST/PUT/PATCH/DELETE) in stateful checks — use with caution")
	fs.BoolVar(&allowWrite, "allow-write", false, "Allow mutating seed requests during scan execution")
	fs.BoolVar(&allowUnsafeRules, "allow-unsafe-rules", false, "Allow destructive, crash, or resource-exhaustion rule probes")
	fs.BoolVar(&allowLiveSSRF, "allow-live-ssrf", false, "Allow live metadata SSRF probes")
	fs.Var(&includeTargets, "target", "Target name to include")
	fs.Var(&excludeTargets, "exclude-target", "Target name to exclude")
	fs.Var(&authContexts, "auth-context", "Auth context name to include")
	fs.Var(&includeOperations, "operation", "Operation ID or locator substring to include (can specify multiple)")
	fs.Var(&includeTags, "tag", "Tag to include — OR logic across multiple values (can specify multiple)")
	fs.IntVar(&concurrency, "concurrency", 0, "Override scan concurrency")
	fs.IntVar(&requestBudget, "request-budget", 0, "Override scan request budget")
	fs.DurationVar(&timeout, "timeout", 0, "Override scan timeout")
	fs.StringVar(&bodyCapture, "body-capture", "", "Body capture profile: redacted or full")
	fs.Var(&followRedirects, "follow-redirects", "Follow HTTP redirects during scan execution")
	fs.BoolVar(&aiEnrich, "ai-enrich", false, "Enrich findings with AI-generated analysis and remediation")
	fs.StringVar(&aiModel, "ai-model", "", "Override AI model for enrichment")
	fs.IntVar(&aiMaxFindings, "ai-max-findings", 0, "Max findings to send for AI enrichment")
	fs.StringVar(&aiOut, "ai-out", "", "Output path for enriched findings JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("scan requires --config")
	}
	hasSpecInput := hasScanSpecInput(openapiPaths, graphqlPaths, protoFiles, descriptorSets, grpcReflectionTargets)
	if strings.TrimSpace(inventoryPath) == "" && !hasSpecInput {
		return fmt.Errorf("scan requires --inventory or a spec input")
	}
	if allowWriteStateful && !stateful {
		return fmt.Errorf("--allow-write-stateful requires --stateful")
	}
	effectiveOutDir := strings.TrimSpace(outDir)
	if effectiveOutDir == "" && hasSpecInput {
		effectiveOutDir = defaultScanOutDir
	}
	if effectiveOutDir != "" {
		if err := os.MkdirAll(effectiveOutDir, 0o700); err != nil {
			return err
		}
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return err
	}
	applyScanOverrides(&cfg, concurrency, requestBudget, timeout, bodyCapture, followRedirects, allowWrite, allowUnsafeRules, allowLiveSSRF)
	applyAIOverrides(&cfg, aiEnrich, aiModel, aiMaxFindings, aiOut)
	if err := cfg.Validate(); err != nil {
		return err
	}

	inv, inventoryArtifactPath, err := loadScanInventory(inventoryPath, openapiPaths, graphqlPaths, protoFiles, protoImportPaths, descriptorSets, grpcReflectionTargets, effectiveOutDir)
	if err != nil {
		return err
	}
	loadedPolicy, hasPolicy, err := loadPolicy(policyPath, cfg.PolicyPath)
	if err != nil {
		return err
	}

	if dryRun {
		return printDryRun(cfg, inv, includeTargets, excludeTargets, includeOperations, includeTags, stateful, hasPolicy, loadedPolicy)
	}

	// Build and resolve the auth registry once so both the seed scan and rule
	// scan share the same login-flow results without executing them twice.
	registry, err := auth.NewRegistry(cfg)
	if err != nil {
		return err
	}
	if err := validateLoginFlowAllowlist(cfg); err != nil {
		return err
	}
	loginClient := &http.Client{
		Timeout: cfg.Scan.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	registry, err = registry.ResolveLoginFlows(context.Background(), loginClient)
	if err != nil {
		return err
	}

	sharedBudget := executor.NewRequestBudget(cfg.Scan.RequestBudget)
	bundle, err := executor.Scan(context.Background(), cfg, inv, executor.ScanOptions{
		IncludeTargets:    includeTargets,
		ExcludeTargets:    excludeTargets,
		AuthContexts:      authContexts,
		ResourceHints:     cfg.ResourceHints,
		Registry:          &registry,
		IncludeOperations: includeOperations,
		IncludeTags:       includeTags,
		Budget:            sharedBudget,
	})
	if err != nil {
		return err
	}

	var schemaFindings []rules.Finding
	var policyFindings []rules.Finding
	if !noRules {
		schemaFindings = filterFindingsByRuleID(schemavalidation.ValidateBundle(&bundle, inv), cfg.Scan.EnabledRules, cfg.Scan.DisabledRules)
		if hasPolicy {
			policyFindings = filterFindingsByRuleID(policyeval.Evaluate(&bundle, inv, cfg.AuthContexts, loadedPolicy), cfg.Scan.EnabledRules, cfg.Scan.DisabledRules)
		}
	}

	// Capture successful requests as seeds (flag > config).
	storePath := strings.TrimSpace(seedStorePath)
	if storePath == "" {
		storePath = strings.TrimSpace(cfg.Output.SeedStorePath)
	}
	if storePath != "" {
		if err := captureSeeds(storePath, bundle, cfg.Scan.BodyCapture); err != nil {
			return err
		}
	}

	// Write evidence bundle.
	data, err := bundleOutputJSON(bundle, cfg.Scan.BodyCapture)
	if err != nil {
		return err
	}
	outputPath := strings.TrimSpace(outPath)
	if outputPath == "" {
		switch {
		case strings.TrimSpace(cfg.Output.EvidencePath) != "":
			outputPath = cfg.Output.EvidencePath
		case strings.TrimSpace(cfg.Output.JSONPath) != "":
			outputPath = cfg.Output.JSONPath
		case effectiveOutDir != "":
			outputPath = filepath.Join(effectiveOutDir, "evidence.json")
		}
	}
	bundleToStdout := outputPath == ""
	if bundleToStdout {
		if _, err = os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
	} else {
		if err = writeFile(outputPath, append(data, '\n')); err != nil {
			return err
		}
	}
	artifacts := []report.Artifact{}
	if inventoryArtifactPath != "" {
		artifacts = append(artifacts, report.Artifact{Kind: "inventory", Path: inventoryArtifactPath})
	}
	if !bundleToStdout {
		artifacts = append(artifacts, report.Artifact{Kind: "evidence", Path: outputPath})
	}
	if storePath != "" {
		artifacts = append(artifacts, report.Artifact{Kind: "seeds", Path: storePath})
	}

	// Coverage summary JSON (flag > config).
	covPath := strings.TrimSpace(coveragePath)
	if covPath == "" {
		covPath = strings.TrimSpace(cfg.Output.CoveragePath)
	}
	if covPath == "" && effectiveOutDir != "" {
		covPath = filepath.Join(effectiveOutDir, "coverage.json")
	}
	if covPath != "" {
		cov := report.BuildCoverageSummary(bundle)
		covData, err := cov.JSON()
		if err != nil {
			return err
		}
		if err := writeFile(covPath, append(covData, '\n')); err != nil {
			return err
		}
		artifacts = append(artifacts, report.Artifact{Kind: "coverage", Path: covPath})
	}

	// Rule-based scanning (skipped when --no-rules is set).
	if noRules {
		if err := writeFindingsArtifact(defaultFindingsPath(findingsPath, cfg.Output.FindingsPath, effectiveOutDir), nil, cfg.Scan.BodyCapture, nil, &artifacts); err != nil {
			return err
		}
		if err := writeSARIFArtifact(defaultSARIFPath(sarifPath, cfg.Output.SARIFPath, effectiveOutDir), nil, nil, &artifacts); err != nil {
			return err
		}
		report.PrintSummaryWithOptions(os.Stderr, bundle, nil, report.SummaryOptions{
			RulesSkipped: true,
			Artifacts:    artifacts,
		})
		return nil
	}
	policy := executor.NewHTTPPolicy(cfg.Scan)
	policy.Budget = sharedBudget
	selectedRules := rules.SelectRules(rules.DefaultRules(), cfg.Scan.EnabledRules, cfg.Scan.DisabledRules, rules.RuleSafety{
		AllowUnsafeRules: cfg.Scan.AllowUnsafeRules,
		AllowLiveSSRF:    cfg.Scan.AllowLiveSSRF,
	})
	findings := append([]rules.Finding(nil), schemaFindings...)
	findings = append(findings, policyFindings...)
	ruleFindings, err := rules.Scan(context.Background(), bundle.Results, registry, selectedRules, policy, rules.ScanOptions{})
	if err != nil {
		return err
	}
	findings = append(findings, ruleFindings...)
	grpcFindings, err := rules.GRPCScan(context.Background(), bundle.Results, cfg.Targets, registry, policy)
	if err != nil {
		return err
	}
	findings = append(findings, grpcFindings...)

	tlsFindings, err := rules.TLSScan(context.Background(), bundle.Results, policy)
	if err != nil {
		return err
	}
	findings = append(findings, tlsFindings...)

	if stateful {
		statefulFindings, err := rules.StatefulScan(context.Background(), bundle.Results, registry, policy, rules.StatefulOptions{
			AllowWriteChecks: allowWriteStateful,
		})
		if err != nil {
			return err
		}
		findings = append(findings, statefulFindings...)
	}

	var findingEnrichments []json.RawMessage
	apiKey := strings.TrimSpace(os.Getenv(cfg.AI.APIKeyEnv))
	if apiKey != "" && len(findings) > 0 {
		var enrichTargets []rules.Finding
		if cfg.AI.Enabled {
			enrichTargets = findings
		} else {
			enrichTargets = enrichment.CriticalFindings(findings)
		}
		if len(enrichTargets) > 0 {
			var enrichErr error
			findingEnrichments, enrichErr = runAutoEnrichment(&cfg, enrichTargets, apiKey, effectiveOutDir, &artifacts)
			if enrichErr != nil {
				fmt.Fprintf(os.Stderr, "AI enrichment: %v\n", enrichErr)
			}
		}
	}

	if err := writeFindingsArtifact(defaultFindingsPath(findingsPath, cfg.Output.FindingsPath, effectiveOutDir), findings, cfg.Scan.BodyCapture, findingEnrichments, &artifacts); err != nil {
		return err
	}
	if err := writeSARIFArtifact(defaultSARIFPath(sarifPath, cfg.Output.SARIFPath, effectiveOutDir), findings, findingEnrichments, &artifacts); err != nil {
		return err
	}

	report.PrintSummaryWithOptions(os.Stderr, bundle, findings, report.SummaryOptions{
		Artifacts:   artifacts,
		Enrichments: enrichmentsToReport(findingEnrichments),
	})

	return nil
}

func applyScanOverrides(cfg *config.Config, concurrency int, requestBudget int, timeout time.Duration, bodyCapture string, followRedirects triStateBool, allowWrite bool, allowUnsafeRules bool, allowLiveSSRF bool) {
	if cfg == nil {
		return
	}
	if concurrency > 0 {
		cfg.Scan.Concurrency = concurrency
	}
	if requestBudget > 0 {
		cfg.Scan.RequestBudget = requestBudget
	}
	if timeout > 0 {
		cfg.Scan.Timeout = timeout
	}
	if strings.TrimSpace(bodyCapture) != "" {
		cfg.Scan.BodyCapture = strings.ToLower(strings.TrimSpace(bodyCapture))
	}
	if followRedirects.set {
		cfg.Scan.FollowRedirects = followRedirects.value
	}
	if allowWrite {
		cfg.Scan.AllowWrite = true
	}
	if allowUnsafeRules {
		cfg.Scan.AllowUnsafeRules = true
	}
	if allowLiveSSRF {
		cfg.Scan.AllowLiveSSRF = true
	}
}

func applyAIOverrides(cfg *config.Config, aiEnrich bool, aiModel string, aiMaxFindings int, aiOut string) {
	if cfg == nil {
		return
	}
	if aiEnrich {
		cfg.AI.Enabled = true
	}
	if strings.TrimSpace(aiModel) != "" {
		cfg.AI.Model = strings.TrimSpace(aiModel)
	}
	if aiMaxFindings > 0 {
		cfg.AI.MaxFindings = aiMaxFindings
	}
	if strings.TrimSpace(aiOut) != "" {
		cfg.AI.OutputPath = strings.TrimSpace(aiOut)
	}
}

func runAutoEnrichment(cfg *config.Config, findings []rules.Finding, apiKey string, outDir string, artifacts *[]report.Artifact) ([]json.RawMessage, error) {
	provider := enrichment.NewTogetherProvider(apiKey)
	maxFindings := cfg.AI.MaxFindings
	if !cfg.AI.Enabled {
		maxFindings = 0
	}
	result := provider.Enrich(findings, enrichment.EnrichOptions{
		MaxFindings:    maxFindings,
		Model:          cfg.AI.Model,
		Timeout:        cfg.AI.Timeout,
		InputBodyLimit: cfg.AI.InputBodyLimit,
	})

	enrichments := make([]json.RawMessage, 0, len(result.Enrichments))
	for _, e := range result.Enrichments {
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		enrichments = append(enrichments, raw)
	}

	if result.EnrichedCount > 0 {
		scope := "critical"
		if cfg.AI.Enabled {
			scope = "all"
		}
		fmt.Fprintf(os.Stderr, "  enriched  %d/%d findings (%s) [%d errors, %d skipped]\n", result.EnrichedCount, len(findings), scope, result.ErrorCount, result.SkippedCount)
	}

	if cfg.AI.Enabled && result.EnrichedCount > 0 {
		enrichedPath := defaultEnrichedPath(cfg.AI.OutputPath, outDir)
		if enrichedPath != "" {
			data, err := result.JSON()
			if err != nil {
				return enrichments, fmt.Errorf("marshal enriched findings: %w", err)
			}
			if err := writeFile(enrichedPath, append(data, '\n')); err != nil {
				return enrichments, err
			}
			*artifacts = append(*artifacts, report.Artifact{Kind: "enriched", Path: enrichedPath})
		}
	}

	if result.ErrorCount > 0 && result.EnrichedCount == 0 {
		return enrichments, fmt.Errorf("all %d enrichment attempts failed", result.ErrorCount)
	}
	return enrichments, nil
}

func defaultEnrichedPath(cfgPath, outDir string) string {
	if path := strings.TrimSpace(cfgPath); path != "" {
		return path
	}
	if strings.TrimSpace(outDir) != "" {
		return filepath.Join(outDir, "findings.enriched.json")
	}
	return ""
}

func enrichmentsToReport(raw []json.RawMessage) []report.FindingEnrichment {
	out := make([]report.FindingEnrichment, 0, len(raw))
	for _, r := range raw {
		var e struct {
			FindingID        string   `json:"finding_id"`
			Summary          string   `json:"summary"`
			Impact           string   `json:"impact"`
			ExploitNarrative string   `json:"exploit_narrative"`
			FixSteps         []string `json:"fix_steps"`
		}
		if json.Unmarshal(r, &e) != nil {
			continue
		}
		out = append(out, report.FindingEnrichment{
			FindingID:        e.FindingID,
			Summary:          e.Summary,
			Impact:           e.Impact,
			ExploitNarrative: e.ExploitNarrative,
			FixSteps:         e.FixSteps,
		})
	}
	return out
}

func filterFindingsByRuleID(findings []rules.Finding, enabledRules []string, disabledRules []string) []rules.Finding {
	if len(findings) == 0 {
		return nil
	}
	enabled := ruleIDSet(enabledRules)
	disabled := ruleIDSet(disabledRules)
	out := make([]rules.Finding, 0, len(findings))
	for _, finding := range findings {
		ruleID := strings.ToUpper(strings.TrimSpace(finding.RuleID))
		if len(enabled) > 0 && !enabled[ruleID] {
			continue
		}
		if disabled[ruleID] {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func loadPolicy(flagPath string, configPath string) (policyeval.Policy, bool, error) {
	path := strings.TrimSpace(flagPath)
	if path == "" {
		path = strings.TrimSpace(configPath)
	}
	if path == "" {
		return policyeval.Policy{}, false, nil
	}
	p, err := policyeval.LoadFile(path)
	if err != nil {
		return policyeval.Policy{}, false, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, true, nil
}

func ruleIDSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		normalized := strings.ToUpper(strings.TrimSpace(value))
		if normalized != "" {
			out[normalized] = true
		}
	}
	return out
}

func hasScanSpecInput(openapiPaths, graphqlPaths, protoFiles, descriptorSets, grpcReflectionTargets []string) bool {
	return len(openapiPaths) > 0 ||
		len(graphqlPaths) > 0 ||
		len(protoFiles) > 0 ||
		len(descriptorSets) > 0 ||
		len(grpcReflectionTargets) > 0
}

func loadScanInventory(inventoryPath string, openapiPaths, graphqlPaths, protoFiles, protoImportPaths, descriptorSets, grpcReflectionTargets []string, outDir string) (inventory.Inventory, string, error) {
	inventories := []inventory.Inventory{}
	if strings.TrimSpace(inventoryPath) != "" {
		inv, err := inventory.LoadInventoryFile(inventoryPath)
		if err != nil {
			return inventory.Inventory{}, "", err
		}
		inventories = append(inventories, inv)
	}

	hasSpecInput := hasScanSpecInput(openapiPaths, graphqlPaths, protoFiles, descriptorSets, grpcReflectionTargets)
	if hasSpecInput {
		inv, err := buildSpecInventory(openapiPaths, graphqlPaths, protoFiles, protoImportPaths, descriptorSets, grpcReflectionTargets)
		if err != nil {
			return inventory.Inventory{}, "", err
		}
		inventories = append(inventories, inv)
	}

	merged := inventory.MergeInventories(inventories...)
	inventoryArtifactPath := ""
	if strings.TrimSpace(outDir) != "" {
		inventoryArtifactPath = filepath.Join(outDir, "inventory.json")
		data, err := merged.JSON()
		if err != nil {
			return inventory.Inventory{}, "", err
		}
		if err := writeFile(inventoryArtifactPath, append(data, '\n')); err != nil {
			return inventory.Inventory{}, "", err
		}
	}
	if hasSpecInput {
		report.PrintDiscoverySummary(os.Stderr, merged, inventoryArtifactPath)
	}
	return merged, inventoryArtifactPath, nil
}

func defaultFindingsPath(flagPath, configPath, outDir string) string {
	if path := strings.TrimSpace(flagPath); path != "" {
		return path
	}
	if path := strings.TrimSpace(configPath); path != "" {
		return path
	}
	if strings.TrimSpace(outDir) != "" {
		return filepath.Join(outDir, "findings.json")
	}
	return ""
}

func defaultSARIFPath(flagPath, configPath, outDir string) string {
	if path := strings.TrimSpace(flagPath); path != "" {
		return path
	}
	if path := strings.TrimSpace(configPath); path != "" {
		return path
	}
	if strings.TrimSpace(outDir) != "" {
		return filepath.Join(outDir, "spekto.sarif")
	}
	return ""
}

func writeFindingsArtifact(path string, findings []rules.Finding, bodyCapture string, enrichments []json.RawMessage, artifacts *[]report.Artifact) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	findingsOutput := findings
	if bodyCapture != "full" {
		findingsOutput = rules.RedactFindings(findings)
	}
	fs := rules.FindingSet{
		Findings:    findingsOutput,
		Summary:     rules.Summarize(findings),
		Enrichments: enrichments,
	}
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(path, append(data, '\n')); err != nil {
		return err
	}
	*artifacts = append(*artifacts, report.Artifact{Kind: "findings", Path: path})
	return nil
}

func writeSARIFArtifact(path string, findings []rules.Finding, enrichments []json.RawMessage, artifacts *[]report.Artifact) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	enrichmentMap := make(map[string]json.RawMessage, len(enrichments))
	for _, e := range enrichments {
		var partial struct {
			FindingID string `json:"finding_id"`
		}
		if json.Unmarshal(e, &partial) == nil && partial.FindingID != "" {
			enrichmentMap[partial.FindingID] = e
		}
	}
	data, err := report.SARIF(findings, enrichmentMap)
	if err != nil {
		return err
	}
	if err := writeFile(path, append(data, '\n')); err != nil {
		return err
	}
	*artifacts = append(*artifacts, report.Artifact{Kind: "sarif", Path: path})
	return nil
}

func validateLoginFlowAllowlist(cfg config.Config) error {
	for _, authContext := range cfg.AuthContexts {
		if authContext.Login == nil {
			continue
		}
		if err := executor.ValidateURLAllowlist(authContext.Login.URL, cfg.Scan.TargetAllowlist); err != nil {
			return fmt.Errorf("auth context %q login url: %w", authContext.Name, err)
		}
	}
	return nil
}

type triStateBool struct {
	set   bool
	value bool
}

func (b *triStateBool) String() string {
	if b == nil || !b.set {
		return ""
	}
	if b.value {
		return "true"
	}
	return "false"
}

func (b *triStateBool) Set(value string) error {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "true", "1", "yes":
		b.set = true
		b.value = true
		return nil
	case "false", "0", "no":
		b.set = true
		b.value = false
		return nil
	default:
		return fmt.Errorf("invalid boolean value %q", value)
	}
}

// printDryRun prints what would be scanned without executing any requests.
func printDryRun(cfg config.Config, inv inventory.Inventory, includeTargets, excludeTargets, includeOperations, includeTags []string, stateful bool, hasPolicy bool, loadedPolicy policyeval.Policy) error {
	fmt.Fprintln(os.Stderr, "Spekto dry run — no requests will be sent")

	targets, err := cfg.SelectTargetsFiltered(includeTargets, excludeTargets)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nTargets (%d):\n", len(targets))
	for _, t := range targets {
		addr := t.BaseURL
		if t.Endpoint != "" {
			addr = t.Endpoint
		}
		fmt.Fprintf(os.Stderr, "  %-20s %s  %s\n", t.Name, strings.ToUpper(t.Protocol), addr)
	}

	selectedOperations := filterDryRunOperations(inv.Operations, targets, includeTargets, excludeTargets, includeOperations, includeTags)
	fmt.Fprintf(os.Stderr, "\nInventory (%d of %d operations selected):\n", len(selectedOperations), inv.Summary.Total)
	shown := 0
	for _, op := range selectedOperations {
		if shown >= 20 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", len(selectedOperations)-shown)
			break
		}
		authReq := string(op.AuthHints.RequiresAuth)
		signals := ""
		if len(op.Signals) > 0 {
			signals = "  signals=" + strings.Join(op.Signals, ",")
		}
		fmt.Fprintf(os.Stderr, "  %-8s  %-50s  conf=%.2f  auth=%s%s\n",
			op.Protocol, op.Locator, op.Confidence, authReq, signals)
		shown++
	}

	fmt.Fprintf(os.Stderr, "\nAuth contexts (%d):\n", len(cfg.AuthContexts))
	for _, a := range cfg.AuthContexts {
		var schemes []string
		if a.BearerToken != "" || a.BearerTokenEnv != "" {
			schemes = append(schemes, "bearer")
		}
		if a.APIKeyHeaderName != "" {
			schemes = append(schemes, "api_key_header")
		}
		if a.APIKeyQueryName != "" {
			schemes = append(schemes, "api_key_query")
		}
		if a.BasicUsername != "" || a.BasicUsernameEnv != "" {
			schemes = append(schemes, "basic")
		}
		roles := ""
		if len(a.Roles) > 0 {
			roles = "  roles=[" + strings.Join(a.Roles, ",") + "]"
		}
		fmt.Fprintf(os.Stderr, "  %-20s schemes=[%s]%s\n", a.Name, strings.Join(schemes, ","), roles)
	}

	statefulNote := "disabled (use --stateful to enable)"
	if stateful {
		statefulNote = "enabled"
	}
	fmt.Fprintf(os.Stderr, "\nRules: %d stateless  Stateful: %s\n", len(rules.DefaultRules()), statefulNote)
	if hasPolicy {
		fmt.Fprintf(os.Stderr, "Policy: %d authz expectation(s), %d custom check(s)\n", len(loadedPolicy.Authorization), len(loadedPolicy.CustomChecks))
	} else {
		fmt.Fprintln(os.Stderr, "Policy: not configured — AUTHZ003-AUTHZ005 and LOGIC001-LOGIC004 are not testable without policy")
	}

	if len(cfg.Scan.TargetAllowlist) > 0 {
		fmt.Fprintf(os.Stderr, "Allowlist: %s\n", strings.Join(cfg.Scan.TargetAllowlist, ", "))
	}
	return nil
}

func filterDryRunOperations(operations []inventory.Operation, targets []config.Target, includeTargets, excludeTargets, includeOperations, includeTags []string) []inventory.Operation {
	filtered := make([]inventory.Operation, 0, len(operations))
	targetFilterSet := len(includeTargets) > 0 || len(excludeTargets) > 0
	for _, op := range operations {
		if targetFilterSet && !dryRunOperationMatchesAnyTarget(op, targets) {
			continue
		}
		if !dryRunOperationMatchesAny(op, includeOperations) {
			continue
		}
		if !dryRunOperationHasAnyTag(op, includeTags) {
			continue
		}
		filtered = append(filtered, op)
	}
	return filtered
}

func dryRunOperationMatchesAny(op inventory.Operation, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	haystacks := []string{
		strings.ToLower(op.ID),
		strings.ToLower(op.Locator),
		strings.ToLower(op.DisplayName),
	}
	for _, filter := range filters {
		needle := strings.ToLower(strings.TrimSpace(filter))
		if needle == "" {
			continue
		}
		for _, haystack := range haystacks {
			if strings.Contains(haystack, needle) {
				return true
			}
		}
	}
	return false
}

func dryRunOperationHasAnyTag(op inventory.Operation, tags []string) bool {
	if len(tags) == 0 {
		return true
	}
	for _, want := range tags {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" {
			continue
		}
		for _, tag := range op.Tags {
			if strings.ToLower(strings.TrimSpace(tag)) == want {
				return true
			}
		}
	}
	return false
}

func dryRunOperationMatchesAnyTarget(op inventory.Operation, targets []config.Target) bool {
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if dryRunOperationMatchesTarget(op, target) {
			return true
		}
	}
	return false
}

func dryRunOperationMatchesTarget(op inventory.Operation, target config.Target) bool {
	if string(op.Protocol) != target.Protocol {
		return false
	}
	if len(op.Targets) == 0 && len(op.Origins) == 0 {
		return true
	}
	targetValues := []string{target.Name}
	if raw := strings.TrimSpace(target.BaseURL); raw != "" {
		targetValues = append(targetValues, raw)
	}
	if raw := strings.TrimSpace(target.Endpoint); raw != "" {
		targetValues = append(targetValues, raw)
	}
	if origin := dryRunTargetOrigin(target); origin != "" {
		targetValues = append(targetValues, origin)
	}
	for _, operationTarget := range append(append([]string{}, op.Targets...), op.Origins...) {
		for _, targetValue := range targetValues {
			if strings.EqualFold(strings.TrimRight(operationTarget, "/"), strings.TrimRight(targetValue, "/")) {
				return true
			}
		}
	}
	return false
}

func dryRunTargetOrigin(target config.Target) string {
	rawURL := strings.TrimSpace(target.BaseURL)
	if rawURL == "" {
		rawURL = strings.TrimSpace(target.Endpoint)
	}
	if rawURL == "" || !strings.Contains(rawURL, "://") {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// writeFile removes any existing file at path before writing data with 0600
// permissions. Removing first ensures the permission mode is always applied,
// even when the file previously existed with weaker permissions.
func writeFile(path string, data []byte) error {
	_ = os.Remove(path)
	return os.WriteFile(path, data, 0o600)
}

const maxInputFileBytes = 20 * 1024 * 1024

func readBoundedFile(path string) ([]byte, error) {
	if err := checkInputFileSize(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func checkInputFileSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > maxInputFileBytes {
		return fmt.Errorf("input %s exceeds %d byte limit", path, maxInputFileBytes)
	}
	return nil
}

// captureSeeds writes successful scan results to the seed store at storePath.
// Existing records for the same (operation, auth context) pair are replaced.
func bundleOutputJSON(bundle executor.Bundle, bodyCapture string) ([]byte, error) {
	if bodyCapture == "full" {
		return bundle.JSON()
	}
	return bundle.RedactedJSON()
}

func resultForSeedCapture(result executor.Result, bodyCapture string) executor.Result {
	if bodyCapture == "full" {
		return result
	}
	return result.Redacted()
}

func captureSeeds(storePath string, bundle executor.Bundle, bodyCapture string) error {
	store, err := seed.LoadStoreFile(storePath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, result := range bundle.Results {
		if result.Status != "succeeded" {
			continue
		}
		captured := resultForSeedCapture(result, bodyCapture)
		store.Add(seed.Record{
			OperationID:     captured.OperationID,
			Locator:         captured.Locator,
			Protocol:        string(captured.Protocol),
			Target:          captured.Target,
			AuthContextName: captured.AuthContextName,
			Method:          captured.Evidence.Request.Method,
			URL:             captured.Evidence.Request.URL,
			Headers:         captured.Evidence.Request.Headers,
			Body:            captured.Evidence.Request.Body,
			ContentType:     captured.Evidence.Request.ContentType,
			GRPCMethod:      captured.Evidence.Request.GRPCMethod,
			Metadata:        captured.Evidence.Request.Metadata,
			ResponseStatus:  captured.Evidence.Response.StatusCode,
			GRPCCode:        captured.Evidence.Response.GRPCCode,
			CapturedAt:      now,
			Source:          "scan",
		})
	}
	return store.Save(storePath)
}
