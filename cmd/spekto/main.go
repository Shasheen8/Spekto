package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	if len(args) < 2 || args[1] != "spec" {
		return fmt.Errorf("unsupported discover subcommand")
	}
	return runDiscoverSpec(args[2:])
}

func runDiscoverSpec(args []string) error {
	fs := flag.NewFlagSet("discover spec", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var openapiPaths multiValue
	var graphqlPaths multiValue
	var protoFiles multiValue
	var protoImportPaths multiValue
	var descriptorSets multiValue
	var harPaths multiValue
	var outPath string

	fs.Var(&openapiPaths, "openapi", "OpenAPI or Swagger file path")
	fs.Var(&graphqlPaths, "graphql-schema", "GraphQL SDL or introspection JSON file path")
	fs.Var(&protoFiles, "proto", "Proto file path")
	fs.Var(&protoImportPaths, "proto-import-path", "Proto import path")
	fs.Var(&descriptorSets, "descriptor-set", "Protobuf descriptor set file path")
	fs.Var(&harPaths, "har", "HAR file path")
	fs.StringVar(&outPath, "out", "", "Output path for canonical inventory JSON")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(openapiPaths) == 0 && len(graphqlPaths) == 0 && len(protoFiles) == 0 && len(descriptorSets) == 0 && len(harPaths) == 0 {
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
	return fmt.Errorf("usage: spekto discover spec [--openapi path] [--graphql-schema path] [--proto path --proto-import-path dir] [--descriptor-set path] [--out file]")
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
