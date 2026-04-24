package inventory

import "strings"

const redactedValue = "[redacted]"
const maxExampleValueBytes = 256

func RedactExample(name, in, value string) string {
	if value == "" {
		return value
	}
	if isSensitiveExampleName(name, in) {
		return redactedValue
	}
	if len(value) > maxExampleValueBytes {
		return value[:maxExampleValueBytes] + "...[truncated]"
	}
	return value
}

func RedactBodyExample(value string) string {
	if value == "" {
		return value
	}
	if len(value) > maxExampleValueBytes {
		return value[:maxExampleValueBytes] + "...[truncated]"
	}
	return redactSensitiveBodyFields(value)
}

func isSensitiveExampleName(name, in string) bool {
	lowerName := strings.ToLower(strings.TrimSpace(name))
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "header":
		switch lowerName {
		case "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization":
			return true
		}
	case "cookie":
		return true
	}
	for _, marker := range []string{"token", "secret", "password", "credential", "api_key", "apikey", "access_key", "private_key"} {
		if strings.Contains(lowerName, marker) {
			return true
		}
	}
	return false
}

func redactSensitiveBodyFields(value string) string {
	out := value
	for _, marker := range []string{"token", "secret", "password", "credential", "api_key", "apikey", "access_key", "private_key"} {
		if strings.Contains(strings.ToLower(out), marker) {
			return redactedValue
		}
	}
	return out
}
