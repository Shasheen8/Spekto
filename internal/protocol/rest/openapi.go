package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

type VersionFamily string

const (
	VersionFamilySwagger20 VersionFamily = "swagger_2_0"
	VersionFamilyOpenAPI30 VersionFamily = "openapi_3_0"
	VersionFamilyOpenAPI31 VersionFamily = "openapi_3_1"
	VersionFamilyOpenAPI32 VersionFamily = "openapi_3_2"
)

type Document struct {
	DeclaredVersion string
	ParserFamily    VersionFamily
	SupportLevel    inventory.SupportLevel
	Warnings        []string
	Operations      []inventory.Operation
	SourceRef       inventory.SourceRef
}

func ParseFile(ctx context.Context, path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	version, family, level, warnings, err := detectVersion(data)
	if err != nil {
		return nil, err
	}

	doc := &Document{
		DeclaredVersion: version,
		ParserFamily:    family,
		SupportLevel:    level,
		Warnings:        append([]string(nil), warnings...),
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     path,
			ParserFamily: string(family),
			SupportLevel: level,
			Warnings:     append([]string(nil), warnings...),
		},
	}

	switch {
	case strings.HasPrefix(version, "2.0"):
		doc3, err := parseSwagger2(data)
		if err != nil {
			return nil, err
		}
		ops, extractWarnings := extractOpenAPI3(doc3, doc.SourceRef)
		doc.Warnings = append(doc.Warnings, extractWarnings...)
		doc.SourceRef.Warnings = append(doc.SourceRef.Warnings, extractWarnings...)
		doc.Operations = ops
		return doc, nil
	case strings.HasPrefix(version, "3."):
		doc3, err := parseOpenAPI3File(ctx, path)
		if err != nil {
			return nil, err
		}
		ops, extractWarnings := extractOpenAPI3(doc3, doc.SourceRef)
		doc.Warnings = append(doc.Warnings, extractWarnings...)
		doc.SourceRef.Warnings = append(doc.SourceRef.Warnings, extractWarnings...)
		doc.Operations = ops
		return doc, nil
	default:
		return nil, fmt.Errorf("unsupported spec version: %s", version)
	}
}

func ParseData(ctx context.Context, data []byte, source string) (*Document, error) {
	version, family, level, warnings, err := detectVersion(data)
	if err != nil {
		return nil, err
	}

	doc := &Document{
		DeclaredVersion: version,
		ParserFamily:    family,
		SupportLevel:    level,
		Warnings:        append([]string(nil), warnings...),
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     source,
			ParserFamily: string(family),
			SupportLevel: level,
			Warnings:     append([]string(nil), warnings...),
		},
	}

	switch {
	case strings.HasPrefix(version, "2.0"):
		doc3, err := parseSwagger2(data)
		if err != nil {
			return nil, err
		}
		ops, extractWarnings := extractOpenAPI3(doc3, doc.SourceRef)
		doc.Warnings = append(doc.Warnings, extractWarnings...)
		doc.SourceRef.Warnings = append(doc.SourceRef.Warnings, extractWarnings...)
		doc.Operations = ops
		return doc, nil
	case strings.HasPrefix(version, "3."):
		doc3, err := parseOpenAPI3(ctx, data, source)
		if err != nil {
			return nil, err
		}
		ops, extractWarnings := extractOpenAPI3(doc3, doc.SourceRef)
		doc.Warnings = append(doc.Warnings, extractWarnings...)
		doc.SourceRef.Warnings = append(doc.SourceRef.Warnings, extractWarnings...)
		doc.Operations = ops
		return doc, nil
	default:
		return nil, fmt.Errorf("unsupported spec version: %s", version)
	}
}

func detectVersion(data []byte) (string, VersionFamily, inventory.SupportLevel, []string, error) {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return "", "", inventory.SupportLevelUnsupported, nil, err
	}

	if raw, ok := root["swagger"]; ok {
		version := strings.TrimSpace(fmt.Sprint(raw))
		if version == "2.0" {
			return version, VersionFamilySwagger20, inventory.SupportLevelFull, nil, nil
		}
		return version, VersionFamilySwagger20, inventory.SupportLevelPartial, []string{"unknown swagger version family"}, nil
	}

	if raw, ok := root["openapi"]; ok {
		version := strings.TrimSpace(fmt.Sprint(raw))
		switch {
		case strings.HasPrefix(version, "3.0."):
			return version, VersionFamilyOpenAPI30, inventory.SupportLevelFull, nil, nil
		case strings.HasPrefix(version, "3.1."):
			return version, VersionFamilyOpenAPI31, inventory.SupportLevelFull, nil, nil
		case strings.HasPrefix(version, "3.2."):
			return version, VersionFamilyOpenAPI32, inventory.SupportLevelFull, nil, nil
		case strings.HasPrefix(version, "3."):
			return version, VersionFamily("openapi_future"), inventory.SupportLevelPartial, []string{"newer OpenAPI 3.x family detected; parsing may be partial"}, nil
		default:
			return version, VersionFamily("openapi_unknown"), inventory.SupportLevelPartial, []string{"unknown OpenAPI version family"}, nil
		}
	}

	return "", "", inventory.SupportLevelUnsupported, nil, errors.New("document is missing openapi or swagger version field")
}

func parseSwagger2(data []byte) (*openapi3.T, error) {
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	jsonReady := toJSONCompatible(raw)
	encoded, err := json.Marshal(jsonReady)
	if err != nil {
		return nil, err
	}
	var doc2 openapi2.T
	if err := json.Unmarshal(encoded, &doc2); err != nil {
		return nil, err
	}
	return openapi2conv.ToV3(&doc2)
}

func parseOpenAPI3(ctx context.Context, data []byte, source string) (*openapi3.T, error) {
	if source != "" {
		if u, err := url.Parse(source); err == nil && u.Scheme != "" && u.Host != "" {
			loader := openapi3.NewLoader()
			loader.Context = ctx
			loader.IsExternalRefsAllowed = true
			return loader.LoadFromDataWithPath(data, u)
		}
	}
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = true
	return loader.LoadFromData(data)
}

func parseOpenAPI3File(ctx context.Context, path string) (*openapi3.T, error) {
	loader := openapi3.NewLoader()
	loader.Context = ctx
	loader.IsExternalRefsAllowed = true
	if abs, err := filepath.Abs(path); err == nil {
		return loader.LoadFromFile(abs)
	}
	return loader.LoadFromFile(path)
}

func extractOpenAPI3(doc *openapi3.T, sourceRef inventory.SourceRef) ([]inventory.Operation, []string) {
	var warnings []string
	if doc == nil {
		return nil, []string{"nil OpenAPI document"}
	}

	servers := extractServers(doc.Servers)
	var operations []inventory.Operation

	paths := make([]string, 0, len(doc.Paths.Map()))
	for path := range doc.Paths.Map() {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		pathItem := doc.Paths.Value(path)
		if pathItem == nil {
			continue
		}
		for _, pair := range pathOperations(pathItem) {
			if pair.op == nil {
				continue
			}
			op := inventory.NewRESTOperation(pair.method, path)
			op.SourceRefs = []inventory.SourceRef{sourceRef}
			op.Provenance = inventory.Provenance{Specified: true}
			op.Confidence = 0.9
			op.Status = inventory.StatusNormalized
			op.Tags = inventory.SortStringsStable(pair.op.Tags)
			op.DisplayName = op.Locator
			op.Targets = append([]string(nil), servers...)
			op.REST = &inventory.RESTDetails{
				Method:           strings.ToUpper(pair.method),
				NormalizedPath:   normalizePath(path),
				OriginalPath:     path,
				ServerCandidates: append([]string(nil), servers...),
				OperationID:      pair.op.OperationID,
				Deprecated:       pair.op.Deprecated,
			}

			allParams := mergeParameters(pathItem.Parameters, pair.op.Parameters)
			for _, paramRef := range allParams {
				if paramRef == nil || paramRef.Value == nil {
					continue
				}
				meta := toParameterMeta(paramRef.Value)
				op.Examples.Parameters = append(op.Examples.Parameters, inventory.ParameterValue{
					Name:     meta.Name,
					In:       meta.In,
					Required: meta.Required,
					Example:  meta.Default,
					Default:  meta.Default,
					Format:   meta.Format,
					Type:     meta.Type,
				})
				switch meta.In {
				case "path":
					op.REST.PathParams = append(op.REST.PathParams, meta)
				case "query":
					op.REST.QueryParams = append(op.REST.QueryParams, meta)
				case "header":
					op.REST.HeaderParams = append(op.REST.HeaderParams, meta)
				case "cookie":
					op.REST.CookieParams = append(op.REST.CookieParams, meta)
				}
			}

			if pair.op.RequestBody != nil && pair.op.RequestBody.Value != nil {
				op.REST.RequestBody = toRequestBodyMeta(pair.op.RequestBody.Value)
				if op.REST.RequestBody != nil {
					op.SchemaRefs.Request = firstSchemaRef(op.REST.RequestBody.SchemaRefs)
					for _, media := range op.REST.RequestBody.Content {
						op.Examples.RequestBodies = append(op.Examples.RequestBodies, inventory.ExampleValue{
							MediaType: media.MediaType,
						})
					}
				}
			}

			op.SchemaRefs.Responses = map[string]string{}
			responseCodes := make([]string, 0, len(pair.op.Responses.Map()))
			for code := range pair.op.Responses.Map() {
				responseCodes = append(responseCodes, code)
			}
			sort.Strings(responseCodes)
			for _, code := range responseCodes {
				respRef := pair.op.Responses.Value(code)
				if respRef == nil || respRef.Value == nil {
					continue
				}
				meta := toResponseMeta(code, respRef.Value)
				op.REST.ResponseMap = append(op.REST.ResponseMap, meta)
				if schemaRef := firstSchemaRef(meta.SchemaRefs); schemaRef != "" {
					op.SchemaRefs.Responses[code] = schemaRef
				}
			}

			op.AuthHints = authHintsFromSecurity(doc.Security, pair.op.Security)
			if len(pair.op.Callbacks) > 0 {
				warnings = append(warnings, fmt.Sprintf("operation %s defines callbacks that are not yet ingested", op.Locator))
			}
			operations = append(operations, op)
		}
	}

	return operations, warnings
}

func extractServers(servers openapi3.Servers) []string {
	if len(servers) == 0 {
		return nil
	}
	values := make([]string, 0, len(servers))
	for _, server := range servers {
		if server == nil {
			continue
		}
		if strings.TrimSpace(server.URL) == "" {
			continue
		}
		values = append(values, strings.TrimSpace(server.URL))
	}
	return inventory.SortStringsStable(values)
}

type methodOperation struct {
	method string
	op     *openapi3.Operation
}

func pathOperations(item *openapi3.PathItem) []methodOperation {
	return []methodOperation{
		{method: "GET", op: item.Get},
		{method: "POST", op: item.Post},
		{method: "PUT", op: item.Put},
		{method: "DELETE", op: item.Delete},
		{method: "PATCH", op: item.Patch},
		{method: "HEAD", op: item.Head},
		{method: "OPTIONS", op: item.Options},
		{method: "TRACE", op: item.Trace},
	}
}

func mergeParameters(pathParams openapi3.Parameters, opParams openapi3.Parameters) openapi3.Parameters {
	merged := append(openapi3.Parameters{}, pathParams...)
	seen := make(map[string]struct{}, len(opParams))
	for _, param := range opParams {
		if param == nil || param.Value == nil {
			continue
		}
		seen[param.Value.In+":"+param.Value.Name] = struct{}{}
	}
	filtered := merged[:0]
	for _, param := range merged {
		if param == nil || param.Value == nil {
			continue
		}
		if _, ok := seen[param.Value.In+":"+param.Value.Name]; ok {
			continue
		}
		filtered = append(filtered, param)
	}
	filtered = append(filtered, opParams...)
	return filtered
}

func toParameterMeta(param *openapi3.Parameter) inventory.ParameterMeta {
	meta := inventory.ParameterMeta{
		Name:     param.Name,
		In:       param.In,
		Required: param.Required,
	}
	if param.Schema != nil && param.Schema.Value != nil {
		meta.Type = schemaType(param.Schema.Value)
		meta.Format = param.Schema.Value.Format
		meta.SchemaRef = param.Schema.Ref
		meta.Enum = stringifySlice(param.Schema.Value.Enum)
		if param.Schema.Value.Default != nil {
			meta.Default = stringifyValue(param.Schema.Value.Default)
		}
	}
	if param.Example != nil && meta.Default == "" {
		meta.Default = stringifyValue(param.Example)
	}
	return meta
}

func toRequestBodyMeta(body *openapi3.RequestBody) *inventory.RequestBodyMeta {
	if body == nil {
		return nil
	}
	meta := &inventory.RequestBodyMeta{
		Required:   body.Required,
		SchemaRefs: map[string]string{},
	}
	mediaTypes := make([]string, 0, len(body.Content))
	for mediaType := range body.Content {
		mediaTypes = append(mediaTypes, mediaType)
	}
	sort.Strings(mediaTypes)
	for _, mediaType := range mediaTypes {
		content := body.Content.Get(mediaType)
		schemaRef := ""
		if content != nil && content.Schema != nil {
			schemaRef = content.Schema.Ref
			meta.SchemaRefs[mediaType] = schemaRef
		}
		meta.Content = append(meta.Content, inventory.MediaTypeMeta{
			MediaType: mediaType,
			SchemaRef: schemaRef,
		})
	}
	return meta
}

func toResponseMeta(code string, response *openapi3.Response) inventory.ResponseMeta {
	meta := inventory.ResponseMeta{
		StatusCode: code,
		SchemaRefs: map[string]string{},
	}
	mediaTypes := make([]string, 0, len(response.Content))
	for mediaType := range response.Content {
		mediaTypes = append(mediaTypes, mediaType)
	}
	sort.Strings(mediaTypes)
	for _, mediaType := range mediaTypes {
		content := response.Content.Get(mediaType)
		schemaRef := ""
		if content != nil && content.Schema != nil {
			schemaRef = content.Schema.Ref
			meta.SchemaRefs[mediaType] = schemaRef
		}
		meta.Content = append(meta.Content, inventory.MediaTypeMeta{
			MediaType: mediaType,
			SchemaRef: schemaRef,
		})
	}
	return meta
}

func authHintsFromSecurity(global openapi3.SecurityRequirements, op *openapi3.SecurityRequirements) inventory.AuthHints {
	reqs := global
	if op != nil {
		reqs = *op
	}
	hints := inventory.AuthHints{
		RequiresAuth: inventory.AuthRequirementUnknown,
	}
	if reqs == nil {
		return hints
	}
	if len(reqs) == 0 {
		hints.RequiresAuth = inventory.AuthRequirementNo
		return hints
	}
	hints.RequiresAuth = inventory.AuthRequirementYes
	hints.AuthSource = inventory.AuthSourceSpec
	schemeSet := map[inventory.AuthScheme]struct{}{}
	for _, req := range reqs {
		for name := range req {
			switch {
			case strings.Contains(strings.ToLower(name), "bearer"), strings.Contains(strings.ToLower(name), "jwt"), strings.Contains(strings.ToLower(name), "oauth"):
				schemeSet[inventory.AuthSchemeBearer] = struct{}{}
			case strings.Contains(strings.ToLower(name), "basic"):
				schemeSet[inventory.AuthSchemeBasic] = struct{}{}
			case strings.Contains(strings.ToLower(name), "cookie"):
				schemeSet[inventory.AuthSchemeCookie] = struct{}{}
			case strings.Contains(strings.ToLower(name), "mtls"), strings.Contains(strings.ToLower(name), "tls"):
				schemeSet[inventory.AuthSchemeMTLS] = struct{}{}
			case strings.Contains(strings.ToLower(name), "query"):
				schemeSet[inventory.AuthSchemeAPIKeyQuery] = struct{}{}
			case strings.Contains(strings.ToLower(name), "key"), strings.Contains(strings.ToLower(name), "header"):
				schemeSet[inventory.AuthSchemeAPIKeyHeader] = struct{}{}
			default:
				schemeSet[inventory.AuthSchemeUnknown] = struct{}{}
			}
		}
	}
	for scheme := range schemeSet {
		hints.AuthSchemes = append(hints.AuthSchemes, scheme)
	}
	sort.Slice(hints.AuthSchemes, func(i, j int) bool { return hints.AuthSchemes[i] < hints.AuthSchemes[j] })
	return hints
}

func firstSchemaRef(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return m[keys[0]]
}

func stringifySlice(values []any) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, stringifyValue(value))
	}
	return out
}

func stringifyValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		encoded, _ := json.Marshal(v)
		return string(encoded)
	}
}

func schemaType(schema *openapi3.Schema) string {
	if schema == nil || schema.Type == nil || len(*schema.Type) == 0 {
		return ""
	}
	return (*schema.Type)[0]
}

func toJSONCompatible(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, val := range v {
			out[key] = toJSONCompatible(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, val := range v {
			out[fmt.Sprint(key)] = toJSONCompatible(val)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, toJSONCompatible(item))
		}
		return out
	default:
		return v
	}
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}
