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

	"github.com/Shasheen8/Spekto/internal/config"
	activediscovery "github.com/Shasheen8/Spekto/internal/discovery/active"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	graphqldiscovery "github.com/Shasheen8/Spekto/internal/protocol/graphql"
	grpcdiscovery "github.com/Shasheen8/Spekto/internal/protocol/grpc"
	restdiscovery "github.com/Shasheen8/Spekto/internal/protocol/rest"
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

	var operationSets [][]inventory.Operation
	for _, path := range inventoryPaths {
		inv, err := inventory.LoadInventoryFile(path)
		if err != nil {
			return fmt.Errorf("inventory %s: %w", path, err)
		}
		operationSets = append(operationSets, inv.Operations)
	}

	return writeMergedInventory(outPath, operationSets...)
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

	return os.WriteFile(outPath, append(data, '\n'), 0o600)
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
	var seedStorePath string
	var includeTargets multiValue
	var excludeTargets multiValue
	var authContexts multiValue
	var concurrency int
	var requestBudget int
	var timeout time.Duration
	var followRedirects triStateBool

	fs.StringVar(&configPath, "config", "", "Config file path")
	fs.StringVar(&inventoryPath, "inventory", "", "Canonical inventory JSON file path")
	fs.StringVar(&outPath, "out", "", "Output path for evidence bundle JSON")
	fs.StringVar(&seedStorePath, "seed-store", "", "Path to seed store JSON file (captures successful requests)")
	fs.Var(&includeTargets, "target", "Target name to include")
	fs.Var(&excludeTargets, "exclude-target", "Target name to exclude")
	fs.Var(&authContexts, "auth-context", "Auth context name to include")
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

	bundle, err := executor.Scan(context.Background(), cfg, inv, executor.ScanOptions{
		IncludeTargets: includeTargets,
		ExcludeTargets: excludeTargets,
		AuthContexts:   authContexts,
		ResourceHints:  cfg.ResourceHints,
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
	if outputPath == "" {
		_, err = os.Stdout.Write(append(data, '\n'))
		return err
	}
	return os.WriteFile(outputPath, append(data, '\n'), 0o600)
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
