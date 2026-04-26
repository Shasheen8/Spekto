package schema

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/Shasheen8/Spekto/internal/rules"
)

const (
	ruleUndocumentedStatus = "SCHEMA001"
	ruleShapeMismatch      = "SCHEMA002"
	ruleContractLeak       = "SCHEMA003"
)

type issues struct {
	shape    []string
	contract []string
}

// ValidateBundle passively checks successful REST evidence against persisted
// OpenAPI schema snapshots. It only inspects existing evidence and never sends
// additional probes.
func ValidateBundle(bundle *executor.Bundle, inv inventory.Inventory) []rules.Finding {
	if bundle == nil {
		return nil
	}
	ops := map[string]inventory.Operation{}
	for _, op := range inv.Operations {
		ops[op.ID] = op
	}

	var findings []rules.Finding
	for i := range bundle.Results {
		result := &bundle.Results[i]
		if result.Status != "succeeded" || result.Protocol != inventory.ProtocolREST {
			continue
		}

		op, ok := ops[result.OperationID]
		if !ok || op.REST == nil {
			bundle.AddSchemaGap(i, "schema_validation_missing_operation_metadata")
			continue
		}

		statusMeta, documented := responseForStatus(op.REST.ResponseMap, result.Evidence.Response.StatusCode)
		if !documented {
			findings = append(findings, rules.NewFinding(
				ruleUndocumentedStatus,
				rules.SeverityMedium,
				rules.ConfidenceHigh,
				"Successful response status is not documented",
				fmt.Sprintf("Operation %s returned HTTP %d, but that status is not documented in the OpenAPI response map.", result.Locator, result.Evidence.Response.StatusCode),
				*result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API9:2023 Improper Inventory Management",
				20,
				"Document the successful status code in the OpenAPI spec or fix the API to return an expected success status.",
			))
			continue
		}

		if len(statusMeta.Content) == 0 {
			bundle.AddSchemaGap(i, "schema_validation_no_response_content_schema")
			continue
		}
		contentType := responseContentType(result.Evidence.Response.Headers)
		if strings.TrimSpace(contentType) == "" {
			bundle.AddSchemaGap(i, "schema_validation_missing_response_content_type")
			continue
		}
		media, matched := responseMediaForContentType(statusMeta.Content, contentType)
		if !matched {
			findings = append(findings, rules.NewFinding(
				ruleShapeMismatch,
				rules.SeverityMedium,
				rules.ConfidenceHigh,
				"Response content type is not documented",
				fmt.Sprintf("Operation %s returned content type %q for HTTP %d, but the documented media types are %s.", result.Locator, contentType, result.Evidence.Response.StatusCode, mediaTypes(statusMeta.Content)),
				*result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API8:2023 Security Misconfiguration",
				20,
				"Align the API response content type with the OpenAPI spec or document the returned media type.",
			))
			continue
		}
		if media.Schema == nil {
			bundle.AddSchemaGap(i, "schema_validation_missing_response_schema")
			continue
		}
		if len(result.Evidence.Response.Body) == 0 {
			bundle.AddSchemaGap(i, "schema_validation_missing_response_body")
			continue
		}
		if !isJSONMediaType(contentType) {
			bundle.AddSchemaGap(i, "schema_validation_unsupported_response_media_type")
			continue
		}

		var body any
		if err := json.Unmarshal(result.Evidence.Response.Body, &body); err != nil {
			findings = append(findings, rules.NewFinding(
				ruleShapeMismatch,
				rules.SeverityMedium,
				rules.ConfidenceHigh,
				"Response body is not valid JSON",
				fmt.Sprintf("Operation %s returned %q, but the body is not valid JSON: %v.", result.Locator, contentType, err),
				*result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API8:2023 Security Misconfiguration",
				20,
				"Return valid JSON for documented JSON responses or update the OpenAPI media type.",
			))
			continue
		}

		var found issues
		validateValue(body, *media.Schema, "response", &found)
		if len(found.shape) > 0 {
			findings = append(findings, rules.NewFinding(
				ruleShapeMismatch,
				rules.SeverityMedium,
				rules.ConfidenceHigh,
				"Response body does not match documented schema",
				fmt.Sprintf("Operation %s returned a body that differs from the OpenAPI schema: %s.", result.Locator, strings.Join(found.shape, "; ")),
				*result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API8:2023 Security Misconfiguration",
				20,
				"Fix the response shape or update the OpenAPI schema so clients and scanners can rely on the documented contract.",
			))
		}
		if len(found.contract) > 0 {
			findings = append(findings, rules.NewFinding(
				ruleContractLeak,
				rules.SeverityHigh,
				rules.ConfidenceHigh,
				"Response contract is missing fields or exposes sensitive data",
				fmt.Sprintf("Operation %s returned a response contract issue: %s.", result.Locator, strings.Join(found.contract, "; ")),
				*result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API3:2023 Broken Object Property Level Authorization",
				200,
				"Return all required fields and remove undocumented sensitive fields from API responses.",
			))
		}
	}
	return findings
}

func responseForStatus(responses []inventory.ResponseMeta, status int) (inventory.ResponseMeta, bool) {
	statusText := strconv.Itoa(status)
	for _, response := range responses {
		if response.StatusCode == statusText {
			return response, true
		}
	}
	for _, response := range responses {
		if statusRangeMatches(response.StatusCode, status) {
			return response, true
		}
	}
	for _, response := range responses {
		if strings.EqualFold(response.StatusCode, "default") {
			return response, true
		}
	}
	return inventory.ResponseMeta{}, false
}

func statusRangeMatches(pattern string, status int) bool {
	pattern = strings.ToUpper(strings.TrimSpace(pattern))
	if len(pattern) != 3 || pattern[1:] != "XX" || pattern[0] < '1' || pattern[0] > '5' {
		return false
	}
	return status/100 == int(pattern[0]-'0')
}

func responseMediaForContentType(content []inventory.MediaTypeMeta, contentType string) (inventory.MediaTypeMeta, bool) {
	for _, media := range content {
		if mediaTypeMatches(media.MediaType, contentType) {
			return media, true
		}
	}
	return inventory.MediaTypeMeta{}, false
}

func mediaTypeMatches(expected, actual string) bool {
	expected = mediaTypeBase(expected)
	actual = mediaTypeBase(actual)
	if expected == actual {
		return true
	}
	return strings.HasSuffix(expected, "+json") && strings.HasSuffix(actual, "+json")
}

func mediaTypeBase(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if idx := strings.Index(value, ";"); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	return value
}

func responseContentType(headers map[string]string) string {
	for key, value := range headers {
		if strings.EqualFold(key, "content-type") {
			return value
		}
	}
	return ""
}

func mediaTypes(content []inventory.MediaTypeMeta) string {
	values := make([]string, 0, len(content))
	for _, media := range content {
		values = append(values, media.MediaType)
	}
	return strings.Join(values, ", ")
}

func isJSONMediaType(value string) bool {
	base := mediaTypeBase(value)
	return base == "application/json" || strings.HasSuffix(base, "+json")
}

func validateValue(value any, meta inventory.SchemaMeta, path string, found *issues) {
	if value == nil {
		if !meta.Nullable {
			found.shape = append(found.shape, path+" is null but schema is not nullable")
		}
		return
	}

	switch effectiveType(meta) {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			found.shape = append(found.shape, path+" should be an object")
			return
		}
		for _, name := range meta.Required {
			if v, ok := object[name]; !ok || v == nil {
				found.contract = append(found.contract, path+"."+name+" is required but missing")
			}
		}
		for name, raw := range object {
			child, documented := meta.Properties[name]
			if !documented {
				if isSensitiveField(name) {
					found.contract = append(found.contract, path+"."+name+" is an undocumented sensitive field")
				}
				continue
			}
			validateValue(raw, child, path+"."+name, found)
		}
	case "array":
		array, ok := value.([]any)
		if !ok {
			found.shape = append(found.shape, path+" should be an array")
			return
		}
		if meta.Items == nil {
			return
		}
		for i, item := range array {
			validateValue(item, *meta.Items, fmt.Sprintf("%s[%d]", path, i), found)
		}
	case "string":
		if _, ok := value.(string); !ok {
			found.shape = append(found.shape, path+" should be a string")
			return
		}
		checkEnum(value, meta, path, found)
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			found.shape = append(found.shape, path+" should be an integer")
			return
		}
		checkEnum(value, meta, path, found)
	case "number":
		if _, ok := value.(float64); !ok {
			found.shape = append(found.shape, path+" should be a number")
			return
		}
		checkEnum(value, meta, path, found)
	case "boolean":
		if _, ok := value.(bool); !ok {
			found.shape = append(found.shape, path+" should be a boolean")
			return
		}
		checkEnum(value, meta, path, found)
	default:
		checkEnum(value, meta, path, found)
		if object, ok := value.(map[string]any); ok {
			for name := range object {
				if _, documented := meta.Properties[name]; !documented && isSensitiveField(name) {
					found.contract = append(found.contract, path+"."+name+" is an undocumented sensitive field")
				}
			}
		}
	}
}

func effectiveType(meta inventory.SchemaMeta) string {
	if meta.Type != "" {
		return meta.Type
	}
	if len(meta.Properties) > 0 || len(meta.Required) > 0 {
		return "object"
	}
	if meta.Items != nil {
		return "array"
	}
	return ""
}

func checkEnum(value any, meta inventory.SchemaMeta, path string, found *issues) {
	if len(meta.Enum) == 0 {
		return
	}
	actual := scalarString(value)
	for _, allowed := range meta.Enum {
		if actual == allowed {
			return
		}
	}
	found.shape = append(found.shape, fmt.Sprintf("%s has value %q outside enum [%s]", path, actual, strings.Join(meta.Enum, ", ")))
}

func scalarString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		if math.Trunc(v) == v {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return fmt.Sprint(v)
	}
}

func isSensitiveField(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"password", "passwd", "secret", "token", "api_key", "apikey", "access_key", "private_key", "credential"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
