package seed

import (
	"strings"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// Candidate holds resolved values for a single REST request attempt.
type Candidate struct {
	PathValues  map[string]string
	QueryValues map[string]string
	Body        []byte
	ContentType string
	// SchemaGaps lists "location:name" entries where only a type fallback was used.
	SchemaGaps []string
}

// GenerateRESTCandidate resolves request values from operation metadata and resource hints.
//
// Resolution priority per parameter:
//  1. Resource hint (operator-provided, highest confidence)
//  2. Inventory example (from spec or observed traffic such as HAR/Postman)
//  3. ParameterMeta default
//  4. First non-empty enum value
//  5. Type/format fallback (recorded as a schema gap)
func GenerateRESTCandidate(op inventory.Operation, hints config.ResourceHints) Candidate {
	c := Candidate{
		PathValues:  make(map[string]string),
		QueryValues: make(map[string]string),
	}
	if op.REST == nil {
		return c
	}
	for _, param := range op.REST.PathParams {
		v, gap := resolveParam(param, op.Examples, hints, "path")
		c.PathValues[param.Name] = v
		if gap {
			c.SchemaGaps = append(c.SchemaGaps, "path:"+param.Name)
		}
	}
	for _, param := range op.REST.QueryParams {
		v, gap := resolveParam(param, op.Examples, hints, "query")
		if !param.Required && gap {
			// Skip optional params that would only produce a type fallback —
			// spurious values risk 400 errors without adding coverage value.
			continue
		}
		c.QueryValues[param.Name] = v
		if gap {
			c.SchemaGaps = append(c.SchemaGaps, "query:"+param.Name)
		}
	}
	c.Body, c.ContentType = resolveBody(op)
	return c
}

// resolveParam resolves one parameter following the priority chain.
// Returns the resolved value and whether a type fallback was used (schema gap).
func resolveParam(param inventory.ParameterMeta, examples inventory.Examples, hints config.ResourceHints, location string) (string, bool) {
	// 1. Resource hint.
	if v := hintFor(hints, param.Name, location); v != "" {
		return v, false
	}
	// 2. Inventory example (spec examples or observed traffic payloads).
	for _, ex := range examples.Parameters {
		if !strings.EqualFold(ex.Name, param.Name) || !strings.EqualFold(ex.In, location) {
			continue
		}
		if v := strings.TrimSpace(ex.Example); v != "" {
			return v, false
		}
		if v := strings.TrimSpace(ex.Default); v != "" {
			return v, false
		}
	}
	// 3. ParameterMeta default.
	if v := strings.TrimSpace(param.Default); v != "" {
		return v, false
	}
	// 4. First non-empty enum value.
	for _, e := range param.Enum {
		if v := strings.TrimSpace(e); v != "" {
			return v, false
		}
	}
	// 5. Type/format fallback — schema gap.
	return TypeFallback(param.Type, param.Format), true
}

// resolveBody selects the best available request body and content type.
func resolveBody(op inventory.Operation) ([]byte, string) {
	// Use the first captured example (from spec or observed traffic).
	for _, ex := range op.Examples.RequestBodies {
		if v := strings.TrimSpace(ex.Value); v != "" {
			return []byte(v), ctOrJSON(ex.MediaType)
		}
	}
	if op.REST == nil || op.REST.RequestBody == nil {
		return nil, ""
	}
	// Fall back to empty JSON for JSON-compatible content types.
	for _, ct := range op.REST.RequestBody.Content {
		if isJSONType(ct.MediaType) {
			return []byte("{}"), ctOrJSON(ct.MediaType)
		}
	}
	// Body present but non-JSON — pass media type through with no body.
	if len(op.REST.RequestBody.Content) > 0 {
		return nil, op.REST.RequestBody.Content[0].MediaType
	}
	return nil, ""
}

// hintFor returns the operator-provided hint for a parameter.
// Constants act as a fallback pool across all locations.
func hintFor(hints config.ResourceHints, name, location string) string {
	switch location {
	case "path":
		if v := hints.PathParams[name]; v != "" {
			return v
		}
	case "query":
		if v := hints.QueryParams[name]; v != "" {
			return v
		}
	}
	return hints.Constants[name]
}

// TypeFallback returns a minimal plausible value for a given type and format.
// Format is checked first so uuid/date/email produce correct shapes even when
// the declared type is just "string".
func TypeFallback(typ, format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "uuid":
		return "00000000-0000-0000-0000-000000000000"
	case "date":
		return "2024-01-01"
	case "date-time", "datetime":
		return "2024-01-01T00:00:00Z"
	case "email":
		return "user@example.com"
	case "uri", "url":
		return "https://example.com"
	case "int32", "int64":
		return "1"
	case "float", "double":
		return "1.0"
	}
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "integer", "int":
		return "1"
	case "number", "float", "double":
		return "1.0"
	case "boolean", "bool":
		return "true"
	case "array":
		return "[]"
	default:
		return "sample"
	}
}

func ctOrJSON(mediaType string) string {
	if strings.TrimSpace(mediaType) == "" {
		return "application/json"
	}
	return mediaType
}

func isJSONType(mediaType string) bool {
	return strings.Contains(strings.ToLower(mediaType), "json")
}
