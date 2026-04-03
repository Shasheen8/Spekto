package graphql

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

type SourceKind string

const (
	SourceKindSDL           SourceKind = "sdl"
	SourceKindIntrospection SourceKind = "introspection"
)

type Document struct {
	SourceKind  SourceKind
	Warnings    []string
	Operations  []inventory.Operation
	SourceRef   inventory.SourceRef
	SchemaStats SchemaStats
}

type SchemaStats struct {
	QueryCount        int
	MutationCount     int
	SubscriptionCount int
}

func ParseData(data []byte, source string) (*Document, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, errors.New("graphql document is empty")
	}

	if looksLikeJSON(trimmed) {
		return parseIntrospectionJSON(data, source)
	}
	return parseSDL(trimmed, source)
}

func parseSDL(schemaSDL, source string) (*Document, error) {
	schema, err := gqlparser.LoadSchema(&ast.Source{Name: source, Input: schemaSDL})
	if err != nil {
		return nil, err
	}

	doc := &Document{
		SourceKind: SourceKindSDL,
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     source,
			ParserFamily: "graphql_sdl",
			SupportLevel: inventory.SupportLevelFull,
		},
	}
	doc.Operations = extractSchemaOperations(schema, doc)
	return doc, nil
}

type introspectionEnvelope struct {
	Data introspectionData `json:"data"`
}

type introspectionData struct {
	Schema introspectionSchema `json:"__schema"`
}

type introspectionSchema struct {
	QueryType        *namedType          `json:"queryType"`
	MutationType     *namedType          `json:"mutationType"`
	SubscriptionType *namedType          `json:"subscriptionType"`
	Types            []introspectionType `json:"types"`
}

type namedType struct {
	Name string `json:"name"`
}

type introspectionType struct {
	Kind   string               `json:"kind"`
	Name   string               `json:"name"`
	Fields []introspectionField `json:"fields"`
}

type introspectionField struct {
	Name string               `json:"name"`
	Args []introspectionInput `json:"args"`
	Type introspectionTypeRef `json:"type"`
}

type introspectionInput struct {
	Name         string               `json:"name"`
	Type         introspectionTypeRef `json:"type"`
	DefaultValue *string              `json:"defaultValue"`
}

type introspectionTypeRef struct {
	Kind   string                `json:"kind"`
	Name   string                `json:"name"`
	OfType *introspectionTypeRef `json:"ofType"`
}

func parseIntrospectionJSON(data []byte, source string) (*Document, error) {
	var envelope introspectionEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.Data.Schema.Types == nil {
		return nil, errors.New("graphql introspection JSON is missing data.__schema.types")
	}

	typeMap := make(map[string]introspectionType, len(envelope.Data.Schema.Types))
	for _, typ := range envelope.Data.Schema.Types {
		if typ.Name == "" {
			continue
		}
		typeMap[typ.Name] = typ
	}

	doc := &Document{
		SourceKind: SourceKindIntrospection,
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     source,
			ParserFamily: "graphql_introspection",
			SupportLevel: inventory.SupportLevelFull,
		},
	}

	if envelope.Data.Schema.QueryType != nil {
		doc.Operations = append(doc.Operations, introspectionRootOperations(typeMap, envelope.Data.Schema.QueryType.Name, "query", doc)...)
	}
	if envelope.Data.Schema.MutationType != nil {
		doc.Operations = append(doc.Operations, introspectionRootOperations(typeMap, envelope.Data.Schema.MutationType.Name, "mutation", doc)...)
	}
	if envelope.Data.Schema.SubscriptionType != nil {
		doc.Operations = append(doc.Operations, introspectionRootOperations(typeMap, envelope.Data.Schema.SubscriptionType.Name, "subscription", doc)...)
	}

	sortOperations(doc.Operations)
	return doc, nil
}

func introspectionRootOperations(typeMap map[string]introspectionType, rootName, rootKind string, doc *Document) []inventory.Operation {
	rootType, ok := typeMap[rootName]
	if !ok {
		doc.Warnings = append(doc.Warnings, fmt.Sprintf("missing root type definition for %s", rootName))
		return nil
	}

	switch rootKind {
	case "query":
		doc.SchemaStats.QueryCount += len(rootType.Fields)
	case "mutation":
		doc.SchemaStats.MutationCount += len(rootType.Fields)
	case "subscription":
		doc.SchemaStats.SubscriptionCount += len(rootType.Fields)
	}

	ops := make([]inventory.Operation, 0, len(rootType.Fields))
	for _, field := range rootType.Fields {
		args := make([]string, 0, len(field.Args))
		typeDeps := []string{renderIntrospectionType(field.Type)}
		for _, arg := range field.Args {
			args = append(args, fmt.Sprintf("%s:%s", arg.Name, renderIntrospectionType(arg.Type)))
		}
		sort.Strings(args)
		ops = append(ops, newGraphQLOperation(rootKind, field.Name, args, typeDeps, doc.SourceRef))
	}
	return ops
}

func extractSchemaOperations(schema *ast.Schema, doc *Document) []inventory.Operation {
	var operations []inventory.Operation
	if schema.Query != nil {
		queryOps := schemaRootOperations(schema.Query, "query", doc.SourceRef)
		doc.SchemaStats.QueryCount = len(queryOps)
		operations = append(operations, queryOps...)
	}
	if schema.Mutation != nil {
		mutationOps := schemaRootOperations(schema.Mutation, "mutation", doc.SourceRef)
		doc.SchemaStats.MutationCount = len(mutationOps)
		operations = append(operations, mutationOps...)
	}
	if schema.Subscription != nil {
		subscriptionOps := schemaRootOperations(schema.Subscription, "subscription", doc.SourceRef)
		doc.SchemaStats.SubscriptionCount = len(subscriptionOps)
		operations = append(operations, subscriptionOps...)
	}
	sortOperations(operations)
	return operations
}

func schemaRootOperations(def *ast.Definition, rootKind string, sourceRef inventory.SourceRef) []inventory.Operation {
	ops := make([]inventory.Operation, 0, len(def.Fields))
	for _, field := range def.Fields {
		if strings.HasPrefix(field.Name, "__") {
			continue
		}
		args := make([]string, 0, len(field.Arguments))
		for _, arg := range field.Arguments {
			args = append(args, fmt.Sprintf("%s:%s", arg.Name, renderASTType(arg.Type)))
		}
		sort.Strings(args)
		typeDeps := []string{renderASTType(field.Type)}
		ops = append(ops, newGraphQLOperation(rootKind, field.Name, args, typeDeps, sourceRef))
	}
	return ops
}

func newGraphQLOperation(rootKind, fieldName string, args, typeDeps []string, sourceRef inventory.SourceRef) inventory.Operation {
	signature := fieldName
	if len(args) > 0 {
		signature = fmt.Sprintf("%s(%s)", fieldName, strings.Join(args, ","))
	}
	locator := fmt.Sprintf("%s:%s", rootKind, signature)

	return inventory.Operation{
		ID:          inventory.StableOperationID(inventory.ProtocolGraphQL, locator),
		Protocol:    inventory.ProtocolGraphQL,
		Family:      inventory.FamilyGraphQL,
		Locator:     locator,
		DisplayName: locator,
		SourceRefs:  []inventory.SourceRef{sourceRef},
		Provenance: inventory.Provenance{
			Specified: true,
		},
		Confidence: 0.8,
		AuthHints: inventory.AuthHints{
			RequiresAuth: inventory.AuthRequirementUnknown,
		},
		SchemaRefs: inventory.SchemaRefs{
			Responses: map[string]string{},
		},
		Status: inventory.StatusNormalized,
		GraphQL: &inventory.GraphQLDetails{
			RootKind:       rootKind,
			OperationName:  fieldName,
			ArgumentMap:    args,
			TypeDeps:       typeDeps,
			SelectionHints: nil,
		},
	}
}

func renderASTType(typ *ast.Type) string {
	if typ == nil {
		return ""
	}
	var base string
	if typ.Elem != nil {
		base = "[" + renderASTType(typ.Elem) + "]"
	} else {
		base = typ.NamedType
	}
	if typ.NonNull {
		base += "!"
	}
	return base
}

func renderIntrospectionType(typ introspectionTypeRef) string {
	switch typ.Kind {
	case "NON_NULL":
		if typ.OfType == nil {
			return "!"
		}
		return renderIntrospectionType(*typ.OfType) + "!"
	case "LIST":
		if typ.OfType == nil {
			return "[]"
		}
		return "[" + renderIntrospectionType(*typ.OfType) + "]"
	default:
		return typ.Name
	}
}

func sortOperations(ops []inventory.Operation) {
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Locator == ops[j].Locator {
			return ops[i].ID < ops[j].ID
		}
		return ops[i].Locator < ops[j].Locator
	})
}

func looksLikeJSON(value string) bool {
	return strings.HasPrefix(value, "{")
}
