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

	activediscovery "github.com/Shasheen8/Spekto/internal/discovery/active"
	"github.com/Shasheen8/Spekto/internal/inventory"
	graphqldiscovery "github.com/Shasheen8/Spekto/internal/protocol/graphql"
	grpcdiscovery "github.com/Shasheen8/Spekto/internal/protocol/grpc"
	restdiscovery "github.com/Shasheen8/Spekto/internal/protocol/rest"
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
	if args[0] != "discover" {
		return fmt.Errorf("unsupported command %q", args[0])
	}
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
	return fmt.Errorf("usage: spekto discover spec [...] | spekto discover traffic [--har path] [--postman path] [--access-log path] [--out file] | spekto discover manual [--seed file] [--out file] | spekto discover active [--base-url url] [--grpc-reflection host:port] [--out file] | spekto discover merge [--inventory file] [--out file]")
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
