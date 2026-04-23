package report

import (
	"encoding/json"
	"sort"

	"github.com/Shasheen8/Spekto/internal/rules"
)

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription sarifText          `json:"shortDescription,omitempty"`
	Properties       sarifRuleProps     `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIF produces a SARIF 2.1.0 document from a set of findings.
// The output is accepted by GitHub Advanced Security for display in the
// Security tab when uploaded as a code-scanning artifact.
func SARIF(findings []rules.Finding) ([]byte, error) {
	// Collect unique rules in deterministic order.
	rulesSeen := map[string]sarifRule{}
	for _, f := range findings {
		if _, ok := rulesSeen[f.RuleID]; ok {
			continue
		}
		rulesSeen[f.RuleID] = sarifRule{
			ID:               f.RuleID,
			Name:             f.Title,
			ShortDescription: sarifText{Text: f.Title},
			Properties: sarifRuleProps{
				Tags:             []string{"security", f.OWASP},
				SecuritySeverity: cvssScore(f.Severity),
			},
		}
	}
	driverRules := make([]sarifRule, 0, len(rulesSeen))
	for _, r := range rulesSeen {
		driverRules = append(driverRules, r)
	}
	sort.Slice(driverRules, func(i, j int) bool {
		return driverRules[i].ID < driverRules[j].ID
	})

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		desc := f.Description
		if f.Remediation != "" {
			desc += " Remediation: " + f.Remediation
		}
		r := sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: desc},
		}
		// Point the location at the probe URL when available, falling back to seed.
		probeURL := f.Evidence.Seed.Request.URL
		if f.Evidence.Probe != nil && f.Evidence.Probe.Request.URL != "" {
			probeURL = f.Evidence.Probe.Request.URL
		}
		if probeURL != "" {
			r.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: probeURL},
				},
			}}
		}
		results = append(results, r)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "Spekto",
					Version:        "1.0.0",
					InformationURI: "https://github.com/Shasheen8/Spekto",
					Rules:          driverRules,
				},
			},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func sarifLevel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// cvssScore returns an approximate CVSS-like score string used by GitHub to
// assign alert severity levels in the Security tab.
func cvssScore(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "9.5"
	case rules.SeverityHigh:
		return "7.5"
	case rules.SeverityMedium:
		return "5.0"
	case rules.SeverityLow:
		return "2.5"
	default:
		return "0.0"
	}
}
