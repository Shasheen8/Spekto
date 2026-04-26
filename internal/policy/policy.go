package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/Shasheen8/Spekto/internal/rules"
	"gopkg.in/yaml.v3"
)

type Policy struct {
	Authorization []AuthorizationPolicy `yaml:"authorization,omitempty" json:"authorization,omitempty"`
	CustomChecks  []CustomCheck         `yaml:"custom_checks,omitempty" json:"custom_checks,omitempty"`
}

type AuthorizationPolicy struct {
	ID                  string              `yaml:"id,omitempty" json:"id,omitempty"`
	Operation           string              `yaml:"operation,omitempty" json:"operation,omitempty"`
	Tags                []string            `yaml:"tags,omitempty" json:"tags,omitempty"`
	DeniedAuthContexts  []string            `yaml:"denied_auth_contexts,omitempty" json:"denied_auth_contexts,omitempty"`
	DeniedRoles         []string            `yaml:"denied_roles,omitempty" json:"denied_roles,omitempty"`
	SensitiveFields     []string            `yaml:"sensitive_fields,omitempty" json:"sensitive_fields,omitempty"`
	TenantParameters    []string            `yaml:"tenant_parameters,omitempty" json:"tenant_parameters,omitempty"`
	AllowedTenantValues map[string][]string `yaml:"allowed_tenant_values,omitempty" json:"allowed_tenant_values,omitempty"`
}

type CustomCheck struct {
	ID               string   `yaml:"id,omitempty" json:"id,omitempty"`
	RuleID           string   `yaml:"rule_id,omitempty" json:"rule_id,omitempty"`
	Operation        string   `yaml:"operation,omitempty" json:"operation,omitempty"`
	Tags             []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	AuthContexts     []string `yaml:"auth_contexts,omitempty" json:"auth_contexts,omitempty"`
	ExpectedStatuses []int    `yaml:"expected_statuses,omitempty" json:"expected_statuses,omitempty"`
	ResponseContains string   `yaml:"response_contains,omitempty" json:"response_contains,omitempty"`
}

func LoadFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return LoadData(data)
}

func LoadData(data []byte) (Policy, error) {
	var p Policy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return Policy{}, err
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func (p Policy) Validate() error {
	for _, authz := range p.Authorization {
		if strings.TrimSpace(authz.Operation) == "" && len(authz.Tags) == 0 {
			return fmt.Errorf("authorization policy %q needs operation or tags", authz.ID)
		}
		if len(authz.DeniedAuthContexts) == 0 && len(authz.DeniedRoles) == 0 && len(authz.SensitiveFields) == 0 && len(authz.TenantParameters) == 0 {
			return fmt.Errorf("authorization policy %q needs at least one authorization expectation", authz.ID)
		}
	}
	for _, check := range p.CustomChecks {
		ruleID := strings.ToUpper(strings.TrimSpace(check.RuleID))
		switch ruleID {
		case "", "LOGIC001", "LOGIC002", "LOGIC003", "LOGIC004":
		default:
			return fmt.Errorf("custom check %q has unsupported rule_id %q", check.ID, check.RuleID)
		}
		if len(check.ExpectedStatuses) == 0 && strings.TrimSpace(check.ResponseContains) == "" {
			return fmt.Errorf("custom check %q needs expected_statuses or response_contains", check.ID)
		}
		if strings.TrimSpace(check.Operation) == "" && len(check.Tags) == 0 {
			return fmt.Errorf("custom check %q needs operation or tags", check.ID)
		}
	}
	return nil
}

func Evaluate(bundle *executor.Bundle, inv inventory.Inventory, authContexts []config.AuthContext, p Policy) []rules.Finding {
	if bundle == nil {
		return nil
	}
	operations := map[string]inventory.Operation{}
	for _, op := range inv.Operations {
		operations[op.ID] = op
	}
	rolesByContext := map[string][]string{}
	for _, ctx := range authContexts {
		rolesByContext[ctx.Name] = ctx.Roles
	}

	var findings []rules.Finding
	for i := range bundle.Results {
		result := &bundle.Results[i]
		if result.Status != "succeeded" || result.Protocol != inventory.ProtocolREST {
			continue
		}
		op, ok := operations[result.OperationID]
		if !ok {
			bundle.AddSchemaGap(i, "policy_missing_operation_metadata")
			continue
		}
		matchedPolicy := false
		for _, authz := range p.Authorization {
			if !authzMatches(authz, op) {
				continue
			}
			matchedPolicy = true
			findings = append(findings, evaluateAuthz(authz, op, *result, rolesByContext[result.AuthContextName])...)
		}
		for _, check := range p.CustomChecks {
			if !customCheckMatches(check, op, *result) {
				continue
			}
			matchedPolicy = true
			if finding, ok := evaluateCustomCheck(check, *result); ok {
				findings = append(findings, finding)
			}
		}
		if !matchedPolicy {
			bundle.AddSchemaGap(i, "policy_missing")
		}
	}
	return findings
}

func evaluateAuthz(authz AuthorizationPolicy, op inventory.Operation, result executor.Result, roles []string) []rules.Finding {
	var findings []rules.Finding
	if stringIn(result.AuthContextName, authz.DeniedAuthContexts) || slices.ContainsFunc(roles, func(role string) bool {
		return stringIn(role, authz.DeniedRoles)
	}) {
		findings = append(findings, rules.NewFinding(
			"AUTHZ005", rules.SeverityHigh, rules.ConfidenceHigh,
			"Operation succeeded despite explicit role/auth policy deny",
			fmt.Sprintf("Operation %s succeeded for auth context %q, but policy %q says this context or role should be denied.", result.Locator, result.AuthContextName, authz.ID),
			result,
			rules.FindingEvidence{Seed: result.Evidence},
			"API5:2023 Broken Function Level Authorization", 862,
			"Enforce server-side authorization for this operation and keep the Spekto policy aligned with intended access.",
		))
	}
	for _, field := range authz.SensitiveFields {
		if jsonFieldPresent(result.Evidence.Response.Body, field) {
			findings = append(findings, rules.NewFinding(
				"AUTHZ003", rules.SeverityHigh, rules.ConfidenceHigh,
				"Sensitive response field exposed contrary to auth policy",
				fmt.Sprintf("Operation %s exposed field %q for auth context %q under policy %q.", op.Locator, field, result.AuthContextName, authz.ID),
				result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API3:2023 Broken Object Property Level Authorization", 200,
				"Remove sensitive fields from lower-privilege responses or enforce field-level authorization before serialization.",
			))
			break
		}
	}
	for _, param := range authz.TenantParameters {
		value := requestParamValue(op, result.Evidence.Request.URL, param)
		if value == "" {
			continue
		}
		allowed := authz.AllowedTenantValues[result.AuthContextName]
		if len(allowed) > 0 && !stringIn(value, allowed) {
			findings = append(findings, rules.NewFinding(
				"AUTHZ004", rules.SeverityHigh, rules.ConfidenceHigh,
				"Tenant boundary policy violation",
				fmt.Sprintf("Operation %s succeeded with %s=%q for auth context %q, but policy %q only allows [%s].", result.Locator, param, value, result.AuthContextName, authz.ID, strings.Join(allowed, ", ")),
				result,
				rules.FindingEvidence{Seed: result.Evidence},
				"API1:2023 Broken Object Level Authorization", 639,
				"Bind tenant/account/org identifiers to the authenticated principal and reject cross-tenant resource access.",
			))
		}
	}
	return findings
}

func evaluateCustomCheck(check CustomCheck, result executor.Result) (rules.Finding, bool) {
	if len(check.ExpectedStatuses) > 0 && !slices.Contains(check.ExpectedStatuses, result.Evidence.Response.StatusCode) {
		return logicFinding(check, result, fmt.Sprintf("expected status [%s], got %d", intList(check.ExpectedStatuses), result.Evidence.Response.StatusCode)), true
	}
	needle := strings.TrimSpace(check.ResponseContains)
	if needle != "" && !strings.Contains(string(result.Evidence.Response.Body), needle) {
		return logicFinding(check, result, fmt.Sprintf("response did not contain %q", needle)), true
	}
	return rules.Finding{}, false
}

func logicFinding(check CustomCheck, result executor.Result, detail string) rules.Finding {
	ruleID := strings.ToUpper(strings.TrimSpace(check.RuleID))
	if ruleID == "" {
		ruleID = "LOGIC001"
	}
	return rules.NewFinding(
		ruleID, rules.SeverityMedium, rules.ConfidenceHigh,
		"Custom business-logic policy check failed",
		fmt.Sprintf("Custom check %q failed for %s: %s.", check.ID, result.Locator, detail),
		result,
		rules.FindingEvidence{Seed: result.Evidence},
		"API6:2023 Unrestricted Access to Sensitive Business Flows", 840,
		"Update the API behavior or the declarative Spekto policy so expected business-flow controls are enforced and documented.",
	)
}

func authzMatches(authz AuthorizationPolicy, op inventory.Operation) bool {
	return operationMatches(authz.Operation, op) || tagsMatch(authz.Tags, op.Tags)
}

func customCheckMatches(check CustomCheck, op inventory.Operation, result executor.Result) bool {
	if !operationMatches(check.Operation, op) && !tagsMatch(check.Tags, op.Tags) {
		return false
	}
	return len(check.AuthContexts) == 0 || stringIn(result.AuthContextName, check.AuthContexts)
}

func operationMatches(pattern string, op inventory.Operation) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	return strings.EqualFold(pattern, op.ID) || strings.EqualFold(pattern, op.Locator)
}

func tagsMatch(want []string, got []string) bool {
	for _, tag := range want {
		if stringIn(tag, got) {
			return true
		}
	}
	return false
}

func stringIn(value string, values []string) bool {
	for _, item := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func jsonFieldPresent(body []byte, field string) bool {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return false
	}
	return jsonFieldPresentInValue(value, field)
}

func jsonFieldPresentInValue(value any, field string) bool {
	object, ok := value.(map[string]any)
	if ok {
		for key, child := range object {
			if strings.EqualFold(key, field) {
				return true
			}
			if jsonFieldPresentInValue(child, field) {
				return true
			}
		}
		return false
	}
	array, ok := value.([]any)
	if ok {
		for _, child := range array {
			if jsonFieldPresentInValue(child, field) {
				return true
			}
		}
	}
	return false
}

func requestParamValue(op inventory.Operation, rawURL, name string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if value := parsed.Query().Get(name); value != "" {
		return value
	}
	if op.REST != nil {
		if value := pathTemplateParamValue(op.REST.NormalizedPath, parsed.Path, name); value != "" {
			return value
		}
		if value := pathTemplateParamValue(op.REST.OriginalPath, parsed.Path, name); value != "" {
			return value
		}
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], name) {
			value, err := url.PathUnescape(parts[i+1])
			if err != nil {
				return parts[i+1]
			}
			return value
		}
	}
	return ""
}

func pathTemplateParamValue(templatePath, requestPath, name string) string {
	templateParts := strings.Split(strings.Trim(templatePath, "/"), "/")
	requestParts := strings.Split(strings.Trim(requestPath, "/"), "/")
	if len(templateParts) == 0 || len(templateParts) != len(requestParts) {
		return ""
	}
	for i, part := range templateParts {
		param := strings.TrimPrefix(strings.TrimSuffix(part, "}"), "{")
		param = strings.TrimPrefix(param, ":")
		if !strings.EqualFold(param, name) || param == part {
			continue
		}
		value, err := url.PathUnescape(requestParts[i])
		if err != nil {
			return requestParts[i]
		}
		return value
	}
	return ""
}

func intList(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ", ")
}
