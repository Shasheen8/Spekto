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
