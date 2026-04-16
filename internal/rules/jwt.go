package rules

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/executor"
)

// jwtParts splits a bearer token into its three base64url parts.
// Returns false when the token is not JWT-shaped.
func jwtParts(token string) (header, payload, sig string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(token), ".", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func decodeJWTHeader(enc string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, err
	}
	return h, nil
}

func encodeJWTHeader(h map[string]any) (string, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hs256Sign(signingInput, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// buildJWTProbe constructs a Probe that sends a tampered JWT and raises a finding
// if the server accepts it (2xx/3xx response).
func buildJWTProbe(ruleID string, seed executor.Result, tampered string,
	severity Severity, title, description, owasp string, cwe int, remediation string,
) Probe {
	req := seedBaseRequest(seed)
	req.ID = probeID(seed, ruleID)
	req.Headers = cloneNonRedactedHeaders(seed.Evidence.Request.Headers)
	req.Headers["Authorization"] = "Bearer " + tampered
	// No AuthContextName → executor will not overwrite our tampered header.

	return Probe{
		RuleID:  ruleID,
		Request: req,
		Evaluate: func(result executor.HTTPResult) []Finding {
			if !probeSucceeded(result) {
				return nil
			}
			return []Finding{newFinding(
				ruleID, severity, ConfidenceHigh,
				title, description,
				seed,
				FindingEvidence{Seed: seed.Evidence, Probe: probeEvidence(result)},
				owasp, cwe, remediation,
			)}
		},
	}
}

// JWTAlgNone checks whether the server accepts a JWT with the algorithm set to "none".
// A server that accepts alg=none performs no signature verification at all.
type JWTAlgNone struct{}

func (r *JWTAlgNone) ID() string { return "JWT001" }

func (r *JWTAlgNone) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	hdr, payload, _, ok := jwtParts(authCtx.BearerToken)
	if !ok {
		return nil, nil
	}
	h, err := decodeJWTHeader(hdr)
	if err != nil {
		return nil, nil
	}
	h["alg"] = "none"
	newHdr, err := encodeJWTHeader(h)
	if err != nil {
		return nil, nil
	}
	// alg=none: unsigned token — empty signature segment.
	tampered := newHdr + "." + payload + "."

	return []Probe{buildJWTProbe(
		r.ID(), seed, tampered,
		SeverityCritical,
		"JWT algorithm confusion: alg=none accepted",
		"The server accepted a JWT with alg=none, meaning it performs no signature verification.",
		"API2:2023 Broken Authentication", 347,
		"Reject JWTs with alg=none. Validate the algorithm against an explicit server-side allowlist before verifying the signature.",
	)}, nil
}

// JWTNullSignature checks whether the server accepts a JWT with an empty signature.
type JWTNullSignature struct{}

func (r *JWTNullSignature) ID() string { return "JWT002" }

func (r *JWTNullSignature) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	hdr, payload, _, ok := jwtParts(authCtx.BearerToken)
	if !ok {
		return nil, nil
	}
	// Original header and payload, signature stripped to empty.
	tampered := hdr + "." + payload + "."

	return []Probe{buildJWTProbe(
		r.ID(), seed, tampered,
		SeverityCritical,
		"JWT null signature accepted",
		"The server accepted a JWT with an empty signature segment, indicating signature validation may not be enforced.",
		"API2:2023 Broken Authentication", 347,
		"Always verify the JWT signature. Reject tokens with empty or missing signatures with 401.",
	)}, nil
}

// JWTBlankSecret checks whether the server accepts a JWT signed with an empty HMAC secret.
type JWTBlankSecret struct{}

func (r *JWTBlankSecret) ID() string { return "JWT003" }

func (r *JWTBlankSecret) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	hdr, payload, _, ok := jwtParts(authCtx.BearerToken)
	if !ok {
		return nil, nil
	}
	h, err := decodeJWTHeader(hdr)
	if err != nil {
		return nil, nil
	}
	h["alg"] = "HS256"
	newHdr, err := encodeJWTHeader(h)
	if err != nil {
		return nil, nil
	}
	sigInput := newHdr + "." + payload
	tampered := sigInput + "." + hs256Sign(sigInput, "")

	return []Probe{buildJWTProbe(
		r.ID(), seed, tampered,
		SeverityHigh,
		"JWT signed with blank secret accepted",
		"The server accepted a JWT signed with an empty HMAC-SHA256 secret.",
		"API2:2023 Broken Authentication", 347,
		"Use a cryptographically strong random secret (minimum 256 bits) for HS256 JWT signing.",
	)}, nil
}

// JWTWeakSecret checks a set of commonly used JWT secrets.
type JWTWeakSecret struct{}

func (r *JWTWeakSecret) ID() string { return "JWT004" }

// commonJWTSecrets is a minimal, high-signal list of frequently used weak secrets.
var commonJWTSecrets = []string{
	"secret", "password", "123456", "qwerty", "admin",
	"letmein", "changeme", "jwt_secret", "your-256-bit-secret",
	"supersecret", "test", "key",
}

func (r *JWTWeakSecret) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	hdr, payload, _, ok := jwtParts(authCtx.BearerToken)
	if !ok {
		return nil, nil
	}
	h, err := decodeJWTHeader(hdr)
	if err != nil {
		return nil, nil
	}
	h["alg"] = "HS256"
	newHdr, err := encodeJWTHeader(h)
	if err != nil {
		return nil, nil
	}
	sigInput := newHdr + "." + payload

	probes := make([]Probe, 0, len(commonJWTSecrets))
	for _, secret := range commonJWTSecrets {
		tampered := sigInput + "." + hs256Sign(sigInput, secret)
		capturedSecret := secret
		probes = append(probes, buildJWTProbe(
			r.ID(), seed, tampered,
			SeverityHigh,
			"JWT signed with weak secret accepted: "+capturedSecret,
			"The server accepted a JWT signed with the common weak secret '"+capturedSecret+"'.",
			"API2:2023 Broken Authentication", 347,
			"Replace the JWT signing secret with a cryptographically strong random value (minimum 256 bits). Store it outside the codebase.",
		))
	}
	return probes, nil
}

// JWTKIDInjection checks whether the JWT kid header parameter is injectable.
// A malicious kid value may cause path traversal or SQL injection in the key lookup.
type JWTKIDInjection struct{}

func (r *JWTKIDInjection) ID() string { return "JWT005" }

var kidPayloads = []string{
	"../../dev/null",
	"' OR '1'='1",
	"/dev/null",
}

func (r *JWTKIDInjection) Check(seed executor.Result, authCtx auth.Context) ([]Probe, []Finding) {
	hdr, payload, sig, ok := jwtParts(authCtx.BearerToken)
	if !ok {
		return nil, nil
	}
	h, err := decodeJWTHeader(hdr)
	if err != nil {
		return nil, nil
	}

	probes := make([]Probe, 0, len(kidPayloads))
	for _, kid := range kidPayloads {
		hCopy := make(map[string]any, len(h))
		for k, v := range h {
			hCopy[k] = v
		}
		hCopy["kid"] = kid
		newHdr, err := encodeJWTHeader(hCopy)
		if err != nil {
			continue
		}
		// Keep original payload and signature — we're only mutating the header.
		tampered := newHdr + "." + payload + "." + sig
		capturedKid := kid
		probes = append(probes, buildJWTProbe(
			r.ID(), seed, tampered,
			SeverityHigh,
			"JWT KID injection",
			"The server accepted a JWT with an injected 'kid' value of '"+capturedKid+"', which may indicate the key ID is not validated before being used in a key lookup.",
			"API2:2023 Broken Authentication", 347,
			"Validate and allowlist JWT kid values. Never interpolate kid directly into filesystem paths or SQL queries.",
		))
	}
	return probes, nil
}
