package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	activediscovery "github.com/Shasheen8/Spekto/internal/discovery/active"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	graphqldiscovery "github.com/Shasheen8/Spekto/internal/protocol/graphql"
	grpcdiscovery "github.com/Shasheen8/Spekto/internal/protocol/grpc"
	restdiscovery "github.com/Shasheen8/Spekto/internal/protocol/rest"
	"github.com/Shasheen8/Spekto/internal/report"
	"github.com/Shasheen8/Spekto/internal/rules"
	"github.com/Shasheen8/Spekto/internal/seed"
)

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
	switch args[0] {
	case "discover":
		if len(args) < 2 {
			return fmt.Errorf("unsupported discover subcommand")
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
			return fmt.Errorf("unsupported discover subcommand")
		}
	case "scan":
		return runScan(args[1:])
	default:
		return fmt.Errorf("unsupported command %q", args[0])
	}
}

func runDiscoverSpec(args []string) error {
	fs := flag.NewFlagSet("discover spec", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var openapiPaths multiValue
	var graphqlPaths multiValue
	var protoFiles multiValue
	var protoImportPaths multiValue
	var descriptorSets multiValue
	var grpcReflectionTargets multiValue
	var outPath string

	fs.Var(&openapiPaths, "openapi", "OpenAPI or Swagger file path")
	fs.Var(&graphqlPaths, "graphql-schema", "GraphQL SDL or introspection JSON file path")
	fs.Var(&protoFiles, "proto", "Proto file path")
	fs.Var(&protoImportPaths, "proto-import-path", "Proto import path")
	fs.Var(&descriptorSets, "descriptor-set", "Protobuf descriptor set file path")
	fs.Var(&grpcReflectionTargets, "grpc-reflection", "gRPC reflection target host:port")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(openapiPaths) == 0 && len(graphqlPaths) == 0 && len(protoFiles) == 0 && len(descriptorSets) == 0 && len(grpcReflectionTargets) == 0 {
		return fmt.Errorf("discover spec requires at least one input source")
	}

	var operationSets [][]inventory.Operation

	for _, path := range openapiPaths {
		doc, err := restdiscovery.ParseFile(context.Background(), path)
		if err != nil {
			return fmt.Errorf("openapi %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	for _, path := range graphqlPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("graphql schema %s: %w", path, err)
		}
		doc, err := graphqldiscovery.ParseData(data, path)
		if err != nil {
			return fmt.Errorf("graphql schema %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	for _, path := range descriptorSets {
		doc, err := grpcdiscovery.ParseDescriptorSetFile(path)
		if err != nil {
			return fmt.Errorf("descriptor set %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}
	for _, target := range grpcReflectionTargets {
		doc, err := grpcdiscovery.ParseReflectionTarget(context.Background(), target)
		if err != nil {
			return fmt.Errorf("grpc reflection %s: %w", target, err)
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
			return fmt.Errorf("proto files: %w", err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	return writeMergedInventory(outPath, operationSets...)
}

func runDiscoverTraffic(args []string) error {
	fs := flag.NewFlagSet("discover traffic", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var harPaths multiValue
	var postmanPaths multiValue
	var accessLogPaths multiValue
	var outPath string

	fs.Var(&harPaths, "har", "HAR file path")
	fs.Var(&postmanPaths, "postman", "Postman collection file path")
	fs.Var(&accessLogPaths, "access-log", "Access log extract file path")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(harPaths) == 0 && len(postmanPaths) == 0 && len(accessLogPaths) == 0 {
		return fmt.Errorf("discover traffic requires at least one traffic input source")
	}

	var operationSets [][]inventory.Operation
	for _, path := range harPaths {
		data, err := os.ReadFile(path)
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
		data, err := os.ReadFile(path)
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

	return writeMergedInventory(outPath, operationSets...)
}

func runDiscoverManual(args []string) error {
	fs := flag.NewFlagSet("discover manual", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var seedPaths multiValue
	var outPath string

	fs.Var(&seedPaths, "seed", "Manual YAML or JSON seed file path")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(seedPaths) == 0 {
		return fmt.Errorf("discover manual requires at least one seed input")
	}

	var operationSets [][]inventory.Operation
	for _, path := range seedPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("seed %s: %w", path, err)
		}
		doc, err := inventory.ParseManual(data, path)
		if err != nil {
			return fmt.Errorf("seed %s: %w", path, err)
		}
		operationSets = append(operationSets, doc.Operations)
	}

	return writeMergedInventory(outPath, operationSets...)
}

func runDiscoverActive(args []string) error {
	fs := flag.NewFlagSet("discover active", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var baseURLs multiValue
	var grpcReflectionTargets multiValue
	var outPath string

	fs.Var(&baseURLs, "base-url", "Base URL to probe for spec and GraphQL endpoints")
	fs.Var(&grpcReflectionTargets, "grpc-reflection", "gRPC reflection target host:port")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")

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

	return writeMergedInventory(outPath, operationSets...)
}

func runDiscoverMerge(args []string) error {
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
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}
	return writeFile(outPath, append(data, '\n'))
}

func writeMergedInventory(outPath string, operationSets ...[]inventory.Operation) error {
	merged := inventory.Merge(operationSets...)
	data, err := merged.JSON()
	if err != nil {
		return err
	}

	if outPath == "" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}

	return writeFile(outPath, append(data, '\n'))
}

func usageError() error {
	return fmt.Errorf("usage: spekto discover spec [...] | spekto discover traffic [--har path] [--postman path] [--access-log path] [--out file] | spekto discover manual [--seed file] [--out file] | spekto discover active [--base-url url] [--grpc-reflection host:port] [--out file] | spekto discover merge [--inventory file] [--out file] | spekto scan --config file --inventory file [--target name] [--exclude-target name] [--auth-context name] [--out file]")
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
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var configPath string
	var inventoryPath string
	var outPath string
	var findingsPath string
	var sarifPath string
	var coveragePath string
	var seedStorePath string
	var noRules bool
	var dryRun bool
	var stateful bool
	var allowWriteStateful bool
	var includeTargets multiValue
	var excludeTargets multiValue
	var authContexts multiValue
	var includeOperations multiValue
	var includeTags multiValue
	var concurrency int
	var requestBudget int
	var timeout time.Duration
	var followRedirects triStateBool

	fs.StringVar(&configPath, "config", "", "Config file path")
	fs.StringVar(&inventoryPath, "inventory", "", "Canonical inventory JSON file path")
	fs.StringVar(&outPath, "out", "", "Output path for evidence bundle JSON")
	fs.StringVar(&findingsPath, "findings-out", "", "Output path for findings JSON (default: prints to stdout when findings exist)")
	fs.StringVar(&sarifPath, "sarif-out", "", "Output path for SARIF findings (for GitHub Advanced Security)")
	fs.StringVar(&coveragePath, "coverage-out", "", "Output path for coverage summary JSON")
	fs.StringVar(&seedStorePath, "seed-store", "", "Path to seed store JSON file (captures successful requests)")
	fs.BoolVar(&noRules, "no-rules", false, "Skip rule-based scanning after seeding")
	fs.BoolVar(&dryRun, "dry-run", false, "Print what would be scanned without sending any requests")
	fs.BoolVar(&stateful, "stateful", false, "Enable stateful authorization checks (BOLA001, BFLA001); requires at least two auth contexts")
	fs.BoolVar(&allowWriteStateful, "allow-write-stateful", false, "Include mutating methods (POST/PUT/PATCH/DELETE) in stateful checks — use with caution")
	fs.Var(&includeTargets, "target", "Target name to include")
	fs.Var(&excludeTargets, "exclude-target", "Target name to exclude")
	fs.Var(&authContexts, "auth-context", "Auth context name to include")
	fs.Var(&includeOperations, "operation", "Operation ID or locator substring to include (can specify multiple)")
	fs.Var(&includeTags, "tag", "Tag to include — OR logic across multiple values (can specify multiple)")
	fs.IntVar(&concurrency, "concurrency", 0, "Override scan concurrency")
	fs.IntVar(&requestBudget, "request-budget", 0, "Override scan request budget")
	fs.DurationVar(&timeout, "timeout", 0, "Override scan timeout")
	fs.Var(&followRedirects, "follow-redirects", "Follow HTTP redirects during scan execution")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("scan requires --config")
	}
	if strings.TrimSpace(inventoryPath) == "" {
		return fmt.Errorf("scan requires --inventory")
	}
	if allowWriteStateful && !stateful {
		return fmt.Errorf("--allow-write-stateful requires --stateful")
	}

	cfg, err := config.LoadFile(configPath)
	if err != nil {
		return err
	}
	applyScanOverrides(&cfg, concurrency, requestBudget, timeout, followRedirects)
	if err := cfg.Validate(); err != nil {
		return err
	}

	inv, err := inventory.LoadInventoryFile(inventoryPath)
	if err != nil {
		return err
	}

	if dryRun {
		return printDryRun(cfg, inv, includeTargets, excludeTargets, stateful)
	}

	// Build and resolve the auth registry once so both the seed scan and rule
	// scan share the same login-flow results without executing them twice.
	registry, err := auth.NewRegistry(cfg)
	if err != nil {
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

	bundle, err := executor.Scan(context.Background(), cfg, inv, executor.ScanOptions{
		IncludeTargets:    includeTargets,
		ExcludeTargets:    excludeTargets,
		AuthContexts:      authContexts,
		ResourceHints:     cfg.ResourceHints,
		Registry:          &registry,
		IncludeOperations: includeOperations,
		IncludeTags:       includeTags,
	})
	if err != nil {
		return err
	}

	// Capture successful requests as seeds (flag > config).
	storePath := strings.TrimSpace(seedStorePath)
	if storePath == "" {
		storePath = strings.TrimSpace(cfg.Output.SeedStorePath)
	}
	if storePath != "" {
		if err := captureSeeds(storePath, bundle); err != nil {
			return err
		}
	}

	// Write evidence bundle.
	data, err := bundle.JSON()
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

	// Rule-based scanning (skipped when --no-rules is set).
	if noRules {
		return nil
	}
	policy := executor.NewHTTPPolicy(cfg.Scan)
	findings, err := rules.Scan(context.Background(), bundle.Results, registry, rules.DefaultRules(), policy, rules.ScanOptions{})
	if err != nil {
		return err
	}
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

	// Human-readable summary always goes to stderr.
	report.PrintSummary(os.Stderr, bundle, findings)

	// Coverage summary JSON (flag > config).
	covPath := strings.TrimSpace(coveragePath)
	if covPath == "" {
		covPath = strings.TrimSpace(cfg.Output.CoveragePath)
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
	}

	if len(findings) == 0 {
		return nil
	}

	// Findings JSON (flag > config).
	fs2 := rules.FindingSet{
		Findings: findings,
		Summary:  rules.Summarize(findings),
	}
	findingsData, err := json.MarshalIndent(fs2, "", "  ")
	if err != nil {
		return err
	}
	findingsData = append(findingsData, '\n')

	fPath := strings.TrimSpace(findingsPath)
	if fPath == "" {
		fPath = strings.TrimSpace(cfg.Output.FindingsPath)
	}
	if fPath != "" {
		if err := writeFile(fPath, findingsData); err != nil {
			return err
		}
	} else if !bundleToStdout {
		if _, err = os.Stdout.Write(findingsData); err != nil {
			return err
		}
	}

	// SARIF (flag > config).
	sPath := strings.TrimSpace(sarifPath)
	if sPath == "" {
		sPath = strings.TrimSpace(cfg.Output.SARIFPath)
	}
	if sPath != "" {
		sarifData, err := report.SARIF(findings)
		if err != nil {
			return err
		}
		if err := writeFile(sPath, append(sarifData, '\n')); err != nil {
			return err
		}
	}

	return nil
}

func applyScanOverrides(cfg *config.Config, concurrency int, requestBudget int, timeout time.Duration, followRedirects triStateBool) {
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
	if followRedirects.set {
		cfg.Scan.FollowRedirects = followRedirects.value
	}
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
func printDryRun(cfg config.Config, inv inventory.Inventory, includeTargets, excludeTargets []string, stateful bool) error {
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

	fmt.Fprintf(os.Stderr, "\nInventory (%d operations):\n", inv.Summary.Total)
	shown := 0
	for _, op := range inv.Operations {
		if shown >= 20 {
			fmt.Fprintf(os.Stderr, "  ... and %d more\n", inv.Summary.Total-shown)
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

	if len(cfg.Scan.TargetAllowlist) > 0 {
		fmt.Fprintf(os.Stderr, "Allowlist: %s\n", strings.Join(cfg.Scan.TargetAllowlist, ", "))
	}
	return nil
}

// writeFile removes any existing file at path before writing data with 0600
// permissions. Removing first ensures the permission mode is always applied,
// even when the file previously existed with weaker permissions.
func writeFile(path string, data []byte) error {
	_ = os.Remove(path)
	return os.WriteFile(path, data, 0o600)
}

// captureSeeds writes successful scan results to the seed store at storePath.
// Existing records for the same (operation, auth context) pair are replaced.
func captureSeeds(storePath string, bundle executor.Bundle) error {
	store, err := seed.LoadStoreFile(storePath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, result := range bundle.Results {
		if result.Status != "succeeded" {
			continue
		}
		store.Add(seed.Record{
			OperationID:     result.OperationID,
			Locator:         result.Locator,
			Protocol:        string(result.Protocol),
			Target:          result.Target,
			AuthContextName: result.AuthContextName,
			Method:          result.Evidence.Request.Method,
			URL:             result.Evidence.Request.URL,
			Headers:         result.Evidence.Request.Headers,
			Body:            result.Evidence.Request.Body,
			ContentType:     result.Evidence.Request.ContentType,
			GRPCMethod:      result.Evidence.Request.GRPCMethod,
			Metadata:        result.Evidence.Request.Metadata,
			ResponseStatus:  result.Evidence.Response.StatusCode,
			GRPCCode:        result.Evidence.Response.GRPCCode,
			CapturedAt:      now,
			Source:          "scan",
		})
	}
	return store.Save(storePath)
}
