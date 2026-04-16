package rules

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
		&JWTKIDInjection{},
		// HTTP misconfiguration
		&SecurityHeaders{},
		&CORSMisconfiguration{},
		&TRACEEnabled{},
		&MethodOverride{},
	}
}
