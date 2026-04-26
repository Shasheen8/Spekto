package policy

import (
	"net/http"
	"testing"

	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

func TestLoadPolicyParsesAuthorizationAndCustomChecks(t *testing.T) {
	doc := []byte(`
authorization:
  - id: admin-deny
    operation: GET:/admin
    denied_auth_contexts: [user]
    sensitive_fields: [admin_secret]
custom_checks:
  - id: amount-limit
    rule_id: LOGIC003
    operation: POST:/checkout
    auth_contexts: [user]
    expected_statuses: [403]
`)

	p, err := LoadData(doc)
	if err != nil {
		t.Fatalf("LoadData returned error: %v", err)
	}
	if len(p.Authorization) != 1 || p.Authorization[0].ID != "admin-deny" {
		t.Fatalf("unexpected authorization policy: %#v", p.Authorization)
	}
	if len(p.CustomChecks) != 1 || p.CustomChecks[0].RuleID != "LOGIC003" {
		t.Fatalf("unexpected custom policy: %#v", p.CustomChecks)
	}
}

func TestLoadPolicyRejectsUnknownFields(t *testing.T) {
	_, err := LoadData([]byte(`
custom_checks:
  - id: amount-limit
    rule_id: LOGIC003
    operation: POST:/checkout
    expected_statuses: [403]
    expected_status: 403
`))
	if err == nil {
		t.Fatalf("expected unknown field to fail")
	}
}

func TestLoadPolicyRejectsRulesWithoutMatchers(t *testing.T) {
	_, err := LoadData([]byte(`
authorization:
  - id: no-match
    denied_auth_contexts: [user]
custom_checks:
  - id: also-no-match
    rule_id: LOGIC003
    expected_statuses: [403]
`))
	if err == nil {
		t.Fatalf("expected matcher-less rules to fail")
	}
}

func TestEvaluateProducesAuthzAndLogicFindings(t *testing.T) {
	p, err := LoadData([]byte(`
authorization:
  - id: admin-deny
    operation: GET:/admin
    denied_auth_contexts: [user]
    sensitive_fields: [admin_secret]
    tenant_parameters: [tenant_id]
    allowed_tenant_values:
      user: [tenant-a]
custom_checks:
  - id: amount-limit
    rule_id: LOGIC003
    operation: GET:/admin
    auth_contexts: [user]
    expected_statuses: [403]
`))
	if err != nil {
		t.Fatalf("LoadData returned error: %v", err)
	}
	op := inventory.NewRESTOperation("GET", "/admin")
	bundle := executor.Bundle{Results: []executor.Result{policyResult(op, "user", "https://api.example.com/admin?tenant_id=tenant-b", `{"admin_secret":"x"}`)}}
	bundle.Finalize()

	findings := Evaluate(&bundle, inventory.Inventory{Operations: []inventory.Operation{op}}, []config.AuthContext{{Name: "user", Roles: []string{"member"}}}, p)

	wantRules := map[string]bool{"AUTHZ003": false, "AUTHZ004": false, "AUTHZ005": false, "LOGIC003": false}
	for _, finding := range findings {
		if _, ok := wantRules[finding.RuleID]; ok {
			wantRules[finding.RuleID] = true
		}
	}
	for ruleID, seen := range wantRules {
		if !seen {
			t.Fatalf("expected %s finding in %#v", ruleID, findings)
		}
	}
}

func TestEvaluateFindsTenantBoundaryViolationInTemplatedPath(t *testing.T) {
	p, err := LoadData([]byte(`
authorization:
  - id: tenant-boundary
    operation: GET:/tenants/{tenant_id}/users
    tenant_parameters: [tenant_id]
    allowed_tenant_values:
      user: [tenant-a]
`))
	if err != nil {
		t.Fatalf("LoadData returned error: %v", err)
	}
	op := inventory.NewRESTOperation("GET", "/tenants/{tenant_id}/users")
	op.REST = &inventory.RESTDetails{
		Method:         "GET",
		NormalizedPath: "/tenants/{tenant_id}/users",
	}
	bundle := executor.Bundle{Results: []executor.Result{policyResult(op, "user", "https://api.example.com/tenants/tenant-b/users", `{"ok":true}`)}}
	bundle.Finalize()

	findings := Evaluate(&bundle, inventory.Inventory{Operations: []inventory.Operation{op}}, []config.AuthContext{{Name: "user"}}, p)

	if len(findings) != 1 || findings[0].RuleID != "AUTHZ004" {
		t.Fatalf("expected AUTHZ004 for templated tenant path, got %#v", findings)
	}
}

func TestEvaluateMatchesDeniedRolesTagsAndResponseContains(t *testing.T) {
	p, err := LoadData([]byte(`
authorization:
  - id: admin-role-deny
    tags: [admin]
    denied_roles: [member]
custom_checks:
  - id: requires-approval-message
    rule_id: LOGIC004
    tags: [admin]
    auth_contexts: [user]
    response_contains: approved
`))
	if err != nil {
		t.Fatalf("LoadData returned error: %v", err)
	}
	op := inventory.NewRESTOperation("GET", "/admin")
	op.Tags = []string{"admin"}
	bundle := executor.Bundle{Results: []executor.Result{policyResult(op, "user", "https://api.example.com/admin", `{"status":"pending"}`)}}
	bundle.Finalize()

	findings := Evaluate(&bundle, inventory.Inventory{Operations: []inventory.Operation{op}}, []config.AuthContext{{Name: "user", Roles: []string{"member"}}}, p)

	wantRules := map[string]bool{"AUTHZ005": false, "LOGIC004": false}
	for _, finding := range findings {
		if _, ok := wantRules[finding.RuleID]; ok {
			wantRules[finding.RuleID] = true
		}
	}
	for ruleID, seen := range wantRules {
		if !seen {
			t.Fatalf("expected %s finding in %#v", ruleID, findings)
		}
	}
}

func TestEvaluateRecordsPolicyMissingCoverageGap(t *testing.T) {
	op := inventory.NewRESTOperation("GET", "/unmapped")
	bundle := executor.Bundle{Results: []executor.Result{policyResult(op, "user", "https://api.example.com/unmapped", `{"ok":true}`)}}
	bundle.Finalize()

	findings := Evaluate(&bundle, inventory.Inventory{Operations: []inventory.Operation{op}}, nil, Policy{})

	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
	if len(bundle.Coverage.Entries) != 1 || len(bundle.Coverage.Entries[0].SchemaGaps) == 0 {
		t.Fatalf("expected policy_missing coverage gap, got %#v", bundle.Coverage)
	}
}

func policyResult(op inventory.Operation, authContext, rawURL, body string) executor.Result {
	return executor.Result{
		Protocol:        inventory.ProtocolREST,
		Target:          "rest-api",
		OperationID:     op.ID,
		Locator:         op.Locator,
		AuthContextName: authContext,
		Status:          "succeeded",
		Evidence: executor.Evidence{
			Request: executor.RequestEvidence{
				Method: http.MethodGet,
				URL:    rawURL,
			},
			Response: executor.ResponseEvidence{
				StatusCode: http.StatusOK,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       []byte(body),
			},
		},
	}
}
