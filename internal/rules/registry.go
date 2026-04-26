package rules

import "strings"

// DefaultRules returns the full v1 rule set in priority order.
// Rules are applied to every successful REST seed result.
func DefaultRules() []Rule {
	return []Rule{
		// Authentication
		&AuthBypass{},
		&InvalidAuthAccepted{},
		// JWT
		&JWTAlgNone{},
		&JWTNullSignature{},
		&JWTBlankSecret{},
		&JWTWeakSecret{},
		&JWTSignatureNotVerified{},
		&JWTKIDInjection{},
		// HTTP misconfiguration
		&SecurityHeaders{},
		&CORSMisconfiguration{},
		&TRACEEnabled{},
		&MethodOverride{},
		&IPSourceBypass{},
		// Parameter and body mutations
		&PrivilegeEscalationParams{},
		&MassAssignment{},
		// GraphQL-specific
		&GraphQLIntrospectionEnabled{},
		&GraphQLAuthBypass{},
		&GraphQLBatchAbuse{},
		// API response XSS / unsafe reflection
		&ReflectedXSS{},
		&StoredXSS{},
		// Injection
		&ServerErrorOnInput{},
		&SQLInjection{},
		&NoSQLInjection{},
		&CommandInjection{},
		&PathTraversal{},
		&SSRFProbe{},
		// Security / disclosure
		&DefaultCredentials{},
		&ServerCrash{},
		&PIIDisclosure{},
		&ResourceExhaustion{},
	}
}

type RuleSafety struct {
	AllowUnsafeRules bool
	AllowLiveSSRF    bool
}

func SelectRules(defaults []Rule, enabled []string, disabled []string, safety RuleSafety) []Rule {
	enabledSet := stringSet(enabled)
	disabledSet := stringSet(disabled)
	selected := make([]Rule, 0, len(defaults))
	for _, rule := range defaults {
		id := strings.ToUpper(strings.TrimSpace(rule.ID()))
		if len(enabledSet) > 0 {
			if _, ok := enabledSet[id]; !ok {
				continue
			}
		}
		if _, ok := disabledSet[id]; ok {
			continue
		}
		if isUnsafeRule(id) && !safety.AllowUnsafeRules {
			continue
		}
		if isLiveSSRFRule(id) && !safety.AllowLiveSSRF {
			continue
		}
		selected = append(selected, rule)
	}
	return selected
}

func isUnsafeRule(id string) bool {
	switch id {
	case "HDR004", "SEC002", "SEC004":
		return true
	default:
		return false
	}
}

func isLiveSSRFRule(id string) bool {
	return id == "INJ006"
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := strings.ToUpper(strings.TrimSpace(value))
		if normalized != "" {
			out[normalized] = struct{}{}
		}
	}
	return out
}
