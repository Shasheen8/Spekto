package inventory

import (
	"encoding/json"
	"sort"
)

type Inventory struct {
	Operations []Operation `json:"operations"`
	Summary    Summary     `json:"summary"`
}

type Summary struct {
	Total          int            `json:"total"`
	ByProtocol     map[string]int `json:"by_protocol,omitempty"`
	SpecifiedCount int            `json:"specified_count"`
	ObservedCount  int            `json:"observed_count"`
	ActiveCount    int            `json:"active_count"`
	ManualCount    int            `json:"manual_count"`
}

func Merge(operationSets ...[]Operation) Inventory {
	index := map[string]Operation{}
	for _, set := range operationSets {
		for _, op := range set {
			if existing, ok := index[op.ID]; ok {
				index[op.ID] = mergeOperation(existing, op)
				continue
			}
			index[op.ID] = op
		}
	}

	ops := make([]Operation, 0, len(index))
	for _, op := range index {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Protocol == ops[j].Protocol {
			if ops[i].Locator == ops[j].Locator {
				return ops[i].ID < ops[j].ID
			}
			return ops[i].Locator < ops[j].Locator
		}
		return ops[i].Protocol < ops[j].Protocol
	})

	return Inventory{
		Operations: ops,
		Summary:    summarize(ops),
	}
}

func (i Inventory) JSON() ([]byte, error) {
	return json.MarshalIndent(i, "", "  ")
}

func mergeOperation(a, b Operation) Operation {
	out := a
	out.Targets = uniqueStrings(append(out.Targets, b.Targets...))
	out.SourceRefs = mergeSourceRefs(out.SourceRefs, b.SourceRefs)
	out.Provenance.Specified = out.Provenance.Specified || b.Provenance.Specified
	out.Provenance.Observed = out.Provenance.Observed || b.Provenance.Observed
	out.Provenance.ActivelyDiscovered = out.Provenance.ActivelyDiscovered || b.Provenance.ActivelyDiscovered
	out.Provenance.ManuallySeeded = out.Provenance.ManuallySeeded || b.Provenance.ManuallySeeded
	out.Confidence = mergedConfidence(out.Confidence, b.Confidence, out.SourceRefs)
	out.AuthHints = mergeAuthHints(out.AuthHints, b.AuthHints)
	out.SchemaRefs = mergeSchemaRefs(out.SchemaRefs, b.SchemaRefs)
	out.Examples = mergeExamples(out.Examples, b.Examples)
	out.Tags = uniqueStrings(append(out.Tags, b.Tags...))
	out.Status = mergeStatus(out.Status, b.Status)
	if out.REST == nil {
		out.REST = b.REST
	}
	if out.GraphQL == nil {
		out.GraphQL = b.GraphQL
	}
	if out.GRPC == nil {
		out.GRPC = b.GRPC
	}
	return out
}

func mergeSourceRefs(a, b []SourceRef) []SourceRef {
	seen := map[string]SourceRef{}
	for _, ref := range append(append([]SourceRef{}, a...), b...) {
		key := string(ref.Type) + "|" + ref.Location + "|" + ref.ParserFamily
		existing, ok := seen[key]
		if !ok {
			seen[key] = ref
			continue
		}
		existing.Warnings = uniqueStrings(append(existing.Warnings, ref.Warnings...))
		if existing.SupportLevel == "" {
			existing.SupportLevel = ref.SupportLevel
		}
		seen[key] = existing
	}
	refs := make([]SourceRef, 0, len(seen))
	for _, ref := range seen {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Type == refs[j].Type {
			return refs[i].Location < refs[j].Location
		}
		return refs[i].Type < refs[j].Type
	})
	return refs
}

func mergedConfidence(a, b float64, refs []SourceRef) float64 {
	max := a
	if b > max {
		max = b
	}
	types := map[SourceType]struct{}{}
	for _, ref := range refs {
		types[ref.Type] = struct{}{}
	}
	boost := float64(len(types)-1) * 0.05
	if boost < 0 {
		boost = 0
	}
	value := max + boost
	if value > 1.0 {
		return 1.0
	}
	return value
}

func mergeAuthHints(a, b AuthHints) AuthHints {
	out := a
	if out.RequiresAuth == AuthRequirementUnknown {
		out.RequiresAuth = b.RequiresAuth
	}
	out.AuthSchemes = uniqueAuthSchemes(append(out.AuthSchemes, b.AuthSchemes...))
	out.AuthContextCandidates = uniqueStrings(append(out.AuthContextCandidates, b.AuthContextCandidates...))
	if out.AuthSource == "" {
		out.AuthSource = b.AuthSource
	}
	return out
}

func mergeSchemaRefs(a, b SchemaRefs) SchemaRefs {
	out := a
	if out.Request == "" {
		out.Request = b.Request
	}
	if out.Responses == nil {
		out.Responses = map[string]string{}
	}
	for code, ref := range b.Responses {
		if out.Responses[code] == "" {
			out.Responses[code] = ref
		}
	}
	return out
}

func mergeExamples(a, b Examples) Examples {
	out := a
	out.RequestBodies = uniqueExampleValues(append(out.RequestBodies, b.RequestBodies...))
	out.Parameters = uniqueParameterValues(append(out.Parameters, b.Parameters...))
	return out
}

func mergeStatus(a, b InventoryStatus) InventoryStatus {
	rank := map[InventoryStatus]int{
		StatusDiscovered:                 0,
		StatusNormalized:                 1,
		StatusSeedable:                   2,
		StatusBlockedMissingSchema:       -1,
		StatusBlockedMissingAuth:         -1,
		StatusBlockedUnsupportedProtocol: -1,
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func summarize(ops []Operation) Summary {
	s := Summary{
		Total:      len(ops),
		ByProtocol: map[string]int{},
	}
	for _, op := range ops {
		s.ByProtocol[string(op.Protocol)]++
		if op.Provenance.Specified {
			s.SpecifiedCount++
		}
		if op.Provenance.Observed {
			s.ObservedCount++
		}
		if op.Provenance.ActivelyDiscovered {
			s.ActiveCount++
		}
		if op.Provenance.ManuallySeeded {
			s.ManualCount++
		}
	}
	return s
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueAuthSchemes(values []AuthScheme) []AuthScheme {
	if len(values) == 0 {
		return nil
	}
	seen := map[AuthScheme]struct{}{}
	out := make([]AuthScheme, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func uniqueExampleValues(values []ExampleValue) []ExampleValue {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]ExampleValue, 0, len(values))
	for _, value := range values {
		key := value.MediaType + "|" + value.Name + "|" + value.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MediaType == out[j].MediaType {
			return out[i].Value < out[j].Value
		}
		return out[i].MediaType < out[j].MediaType
	})
	return out
}

func uniqueParameterValues(values []ParameterValue) []ParameterValue {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]ParameterValue, 0, len(values))
	for _, value := range values {
		key := value.In + "|" + value.Name + "|" + value.Example + "|" + value.Default
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].In == out[j].In {
			return out[i].Name < out[j].Name
		}
		return out[i].In < out[j].In
	})
	return out
}
