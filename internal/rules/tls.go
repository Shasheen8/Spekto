package rules

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/Shasheen8/Spekto/internal/executor"
	"github.com/Shasheen8/Spekto/internal/inventory"
)

// TLSScan inspects the TLS configuration of every unique HTTPS host present in
// the successful seed results. It operates at the TLS transport layer — no HTTP
// requests are sent — so it runs independently of rules.Scan.
//
// Rules applied (once per unique host):
//
//	TLS001 – server accepts TLS 1.0 or 1.1
//	TLS002 – negotiated cipher suite is broken or risky
//	TLS003 – server certificate is expired
//	TLS004 – server certificate chain fails verification
func TLSScan(ctx context.Context, seeds []executor.Result, policy executor.HTTPPolicy) ([]Finding, error) {
	seen := map[string]bool{}
	var allFindings []Finding

	for _, seed := range seeds {
		if seed.Status != "succeeded" {
			continue
		}
		if seed.Protocol != inventory.ProtocolREST && seed.Protocol != inventory.ProtocolGraphQL {
			continue
		}
		host, port := tlsHostPort(seed.Evidence.Request.URL)
		if host == "" {
			continue
		}
		addr := net.JoinHostPort(host, port)
		if seen[addr] {
			continue
		}
		seen[addr] = true

		if policy.Budget != nil && !policy.Budget.Consume() {
			continue
		}
		findings, err := tlsCheckHost(ctx, host, addr, seed, policy.Timeout)
		if err != nil {
			continue // unreachable or non-TLS host — skip silently
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

// tlsHostPort extracts the hostname and port from a URL.
// Returns empty strings for non-HTTPS URLs.
func tlsHostPort(rawURL string) (host, port string) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" {
		return "", ""
	}
	h := parsed.Hostname()
	p := parsed.Port()
	if p == "" {
		p = "443"
	}
	return h, p
}

// tlsCheckHost runs all four TLS checks against a single host.
func tlsCheckHost(ctx context.Context, host, addr string, seed executor.Result, timeout time.Duration) ([]Finding, error) {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Apply the context deadline to the dialer so connections to unreachable
	// hosts do not hang indefinitely.
	dialer := &net.Dialer{}
	if deadline, ok := dialCtx.Deadline(); ok {
		dialer.Deadline = deadline
	}

	var findings []Finding

	// TLS003 & TLS004: connect with standard verification so x509 errors surface.
	conn403, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		// Expired certificate must be classified as TLS003 before checking for
		// other chain errors (x509.CertificateInvalidError covers both).
		var certInvalid x509.CertificateInvalidError
		var unknownAuth x509.UnknownAuthorityError
		var hostMismatch x509.HostnameError
		switch {
		case errors.As(err, &certInvalid) && certInvalid.Reason == x509.Expired:
			findings = append(findings, tlsFinding("TLS003", SeverityHigh, ConfidenceHigh,
				"Expired TLS certificate",
				fmt.Sprintf("The TLS certificate for %s has expired.", host),
				seed,
				"API7:2023 Security Misconfiguration", 298,
				"Renew the TLS certificate before expiry. Configure automated certificate renewal (e.g. Let's Encrypt with ACME).",
			))
		case errors.As(err, &certInvalid) || errors.As(err, &unknownAuth) || errors.As(err, &hostMismatch):
			findings = append(findings, tlsFinding("TLS004", SeverityHigh, ConfidenceHigh,
				"Invalid TLS certificate chain",
				fmt.Sprintf("The server certificate for %s failed verification: %v", host, err),
				seed,
				"API7:2023 Security Misconfiguration", 295,
				"Obtain a certificate from a trusted CA and ensure the full chain is served. Validate the server name matches the certificate.",
			))
		}
		// Certificate errors do not prevent TLS001 — continue to version check.
	} else {
		state := conn403.ConnectionState()
		conn403.Close()

		// TLS003: expiry check on a cert that otherwise verifies.
		for _, cert := range state.PeerCertificates {
			if time.Now().After(cert.NotAfter) {
				findings = append(findings, tlsFinding("TLS003", SeverityHigh, ConfidenceHigh,
					"Expired TLS certificate",
					fmt.Sprintf("The TLS certificate for %s expired on %s.", host, cert.NotAfter.Format("2006-01-02")),
					seed,
					"API7:2023 Security Misconfiguration", 298,
					"Renew the TLS certificate before expiry. Configure automated certificate renewal.",
				))
				break
			}
		}

		// TLS002: inspect the negotiated cipher suite.
		if isRiskyCipher(state.CipherSuite) {
			findings = append(findings, tlsFinding("TLS002", SeverityHigh, ConfidenceMedium,
				"Broken or risky TLS cipher suite",
				fmt.Sprintf("The TLS connection to %s negotiated cipher suite 0x%04X which is considered broken or risky.", host, state.CipherSuite),
				seed,
				"API7:2023 Security Misconfiguration", 326,
				"Configure the server to offer only strong cipher suites (AES-GCM, ChaCha20-Poly1305). Disable export, NULL, RC4, DES, 3DES, and anonymous key exchange ciphers.",
			))
		}
	}

	// TLS001: try to connect forcing TLS 1.0 or 1.1.
	// Success means the server accepts a deprecated protocol version.
	connOld, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
		InsecureSkipVerify: true, //nolint:gosec // intentional — testing server version capability, not identity
	})
	if err == nil {
		state := connOld.ConnectionState()
		connOld.Close()
		ver := tlsVersionName(state.Version)
		findings = append(findings, tlsFinding("TLS001", SeverityHigh, ConfidenceHigh,
			"Weak TLS version accepted: "+ver,
			fmt.Sprintf("The server at %s accepted a TLS handshake using %s, which is a deprecated and insecure protocol version.", host, ver),
			seed,
			"API7:2023 Security Misconfiguration", 326,
			"Configure the server to require TLS 1.2 as the minimum version. Disable TLS 1.0 and TLS 1.1.",
		))
	}

	return findings, nil
}

// tlsFinding constructs a Finding for a TLS rule. TLS findings use the seed
// for target/protocol context but have no probe evidence (no HTTP request sent).
func tlsFinding(ruleID string, severity Severity, confidence Confidence, title, description string, seed executor.Result, owasp string, cwe int, remediation string) Finding {
	return newFinding(ruleID, severity, confidence, title, description, seed,
		FindingEvidence{Seed: seed.Evidence}, owasp, cwe, remediation)
}

// riskyCipherSuites lists cipher suite IDs considered broken or risky.
// These are NULL, RC4, DES/3DES, and anonymous key exchange suites.
// Hex IDs are used where Go does not expose a named constant.
var riskyCipherSuites = map[uint16]bool{
	// NULL ciphers (Go does not expose named constants for these)
	0x0000: true, // TLS_NULL_WITH_NULL_NULL
	0x0001: true, // TLS_RSA_WITH_NULL_MD5
	0x0002: true, // TLS_RSA_WITH_NULL_SHA
	0x003B: true, // TLS_RSA_WITH_NULL_SHA256
	// RC4
	tls.TLS_RSA_WITH_RC4_128_SHA:       true,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA: true,
	0x0004:                             true, // TLS_RSA_WITH_RC4_128_MD5
	// 3DES
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
	0xC008:                                  true, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
}

func isRiskyCipher(suite uint16) bool {
	return riskyCipherSuites[suite]
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04X)", v)
	}
}
