package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	reUUID    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reNumeric = regexp.MustCompile(`^[0-9]+$`)
)

type Protocol string

const (
	ProtocolREST    Protocol = "rest"
	ProtocolGraphQL Protocol = "graphql"
	ProtocolGRPC    Protocol = "grpc"
)

type Family string

const (
	FamilyHTTP    Family = "http"
	FamilyGraphQL Family = "graphql"
	FamilyGRPC    Family = "grpc"
)

type SourceType string

const (
	SourceSpec    SourceType = "spec"
	SourceTraffic SourceType = "traffic"
	SourceActive  SourceType = "active"
	SourceManual  SourceType = "manual"
)

type SupportLevel string

const (
	SupportLevelFull        SupportLevel = "full"
	SupportLevelPartial     SupportLevel = "partial"
	SupportLevelUnsupported SupportLevel = "unsupported"
)

type InventoryStatus string

const (
	StatusDiscovered                 InventoryStatus = "discovered"
	StatusNormalized                 InventoryStatus = "normalized"
	StatusSeedable                   InventoryStatus = "seedable"
	StatusBlockedMissingSchema       InventoryStatus = "blocked_missing_schema"
	StatusBlockedMissingAuth         InventoryStatus = "blocked_missing_auth"
	StatusBlockedUnsupportedProtocol InventoryStatus = "blocked_unsupported_protocol_feature"
)

type AuthRequirement string

const (
	AuthRequirementYes     AuthRequirement = "yes"
	AuthRequirementNo      AuthRequirement = "no"
	AuthRequirementUnknown AuthRequirement = "unknown"
)

type AuthScheme string

const (
	AuthSchemeBearer       AuthScheme = "bearer"
	AuthSchemeAPIKeyHeader AuthScheme = "api_key_header"
	AuthSchemeAPIKeyQuery  AuthScheme = "api_key_query"
	AuthSchemeBasic        AuthScheme = "basic"
	AuthSchemeCookie       AuthScheme = "cookie"
	AuthSchemeMTLS         AuthScheme = "mtls"
	AuthSchemeUnknown      AuthScheme = "unknown"
)

type AuthSource string

const (
	AuthSourceSpec     AuthSource = "spec"
	AuthSourceObserved AuthSource = "observed"
	AuthSourceOperator AuthSource = "operator"
)

type Operation struct {
	ID          string          `json:"id"`
	Protocol    Protocol        `json:"protocol"`
	Family      Family          `json:"family"`
	Locator     string          `json:"locator"`
	DisplayName string          `json:"display_name"`
	Targets     []string        `json:"targets,omitempty"`
	Origins     []string        `json:"origins,omitempty"`
	SourceRefs  []SourceRef     `json:"source_refs,omitempty"`
	Provenance  Provenance      `json:"provenance"`
	Confidence  float64         `json:"confidence"`
	AuthHints   AuthHints       `json:"auth_hints"`
	SchemaRefs  SchemaRefs      `json:"schema_refs"`
	Examples    Examples        `json:"examples,omitempty"`
	Signals     []string        `json:"signals,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Status      InventoryStatus `json:"status"`

	REST    *RESTDetails    `json:"rest,omitempty"`
	GraphQL *GraphQLDetails `json:"graphql,omitempty"`
	GRPC    *GRPCDetails    `json:"grpc,omitempty"`
}

type SourceRef struct {
	Type         SourceType   `json:"type"`
	Location     string       `json:"location"`
	ParserFamily string       `json:"parser_family,omitempty"`
	SupportLevel SupportLevel `json:"support_level,omitempty"`
	Warnings     []string     `json:"warnings,omitempty"`
}

type Provenance struct {
	Specified          bool `json:"specified"`
	Observed           bool `json:"observed"`
	ActivelyDiscovered bool `json:"actively_discovered"`
	ManuallySeeded     bool `json:"manually_seeded"`
}

type AuthHints struct {
	RequiresAuth          AuthRequirement `json:"requires_auth"`
	AuthSchemes           []AuthScheme    `json:"auth_schemes,omitempty"`
	AuthContextCandidates []string        `json:"auth_context_candidates,omitempty"`
	AuthSource            AuthSource      `json:"auth_source,omitempty"`
}

type SchemaRefs struct {
	Request   string            `json:"request,omitempty"`
	Responses map[string]string `json:"responses,omitempty"`
}

type Examples struct {
	RequestBodies []ExampleValue   `json:"request_bodies,omitempty"`
	Parameters    []ParameterValue `json:"parameters,omitempty"`
}

type ExampleValue struct {
	MediaType string `json:"media_type,omitempty"`
	Name      string `json:"name,omitempty"`
	Value     string `json:"value,omitempty"`
}

type ParameterValue struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required,omitempty"`
	Example  string `json:"example,omitempty"`
	Default  string `json:"default,omitempty"`
	Format   string `json:"format,omitempty"`
	Type     string `json:"type,omitempty"`
}

type RESTDetails struct {
	Method           string           `json:"method"`
	NormalizedPath   string           `json:"normalized_path"`
	OriginalPath     string           `json:"original_path"`
	PathParams       []ParameterMeta  `json:"path_params,omitempty"`
	QueryParams      []ParameterMeta  `json:"query_params,omitempty"`
	HeaderParams     []ParameterMeta  `json:"header_params,omitempty"`
	CookieParams     []ParameterMeta  `json:"cookie_params,omitempty"`
	RequestBody      *RequestBodyMeta `json:"request_body,omitempty"`
	ResponseMap      []ResponseMeta   `json:"response_map,omitempty"`
	ServerCandidates []string         `json:"server_candidates,omitempty"`
	OperationID      string           `json:"operation_id,omitempty"`
	Deprecated       bool             `json:"deprecated,omitempty"`
}

type GraphQLDetails struct {
	RootKind       string   `json:"root_kind"`
	OperationName  string   `json:"operation_name,omitempty"`
	ArgumentMap    []string `json:"argument_map,omitempty"`
	SelectionHints []string `json:"selection_hints,omitempty"`
	TypeDeps       []string `json:"type_dependencies,omitempty"`
}

type GRPCDetails struct {
	Package       string `json:"package,omitempty"`
	Service       string `json:"service"`
	RPC           string `json:"rpc"`
	StreamingMode string `json:"streaming_mode"`
	RequestMsg    string `json:"request_message,omitempty"`
	ResponseMsg   string `json:"response_message,omitempty"`
}

type ParameterMeta struct {
	Name      string   `json:"name"`
	In        string   `json:"in"`
	Required  bool     `json:"required,omitempty"`
	Type      string   `json:"type,omitempty"`
	Format    string   `json:"format,omitempty"`
	Enum      []string `json:"enum,omitempty"`
	Default   string   `json:"default,omitempty"`
	SchemaRef string   `json:"schema_ref,omitempty"`
}

type RequestBodyMeta struct {
	Required   bool              `json:"required,omitempty"`
	Content    []MediaTypeMeta   `json:"content,omitempty"`
	SchemaRefs map[string]string `json:"schema_refs,omitempty"`
}

type MediaTypeMeta struct {
	MediaType string `json:"media_type"`
	SchemaRef string `json:"schema_ref,omitempty"`
}

type ResponseMeta struct {
	StatusCode string            `json:"status_code"`
	Content    []MediaTypeMeta   `json:"content,omitempty"`
	SchemaRefs map[string]string `json:"schema_refs,omitempty"`
}

func NewRESTOperation(method, normalizedPath string) Operation {
	method = strings.ToUpper(strings.TrimSpace(method))
	locator := fmt.Sprintf("%s:%s", method, normalizePath(normalizedPath))
	return Operation{
		ID:          StableOperationID(ProtocolREST, locator),
		Protocol:    ProtocolREST,
		Family:      FamilyHTTP,
		Locator:     locator,
		DisplayName: locator,
		Confidence:  0,
		AuthHints: AuthHints{
			RequiresAuth: AuthRequirementUnknown,
		},
		SchemaRefs: SchemaRefs{
			Responses: map[string]string{},
		},
		Status: StatusDiscovered,
	}
}

func StableOperationID(protocol Protocol, locator string) string {
	normalized := strings.TrimSpace(strings.ToLower(string(protocol) + ":" + locator))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:8])
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return path
}

// NormalizeTrafficPath replaces dynamic path segments (UUIDs, integers) with
// named placeholders and returns the normalized path together with the extracted
// parameter examples. Applied to traffic-derived operations (HAR, Postman,
// access logs) so that /v1/users/42 and /v1/users/87 collapse to one operation:
// /v1/users/{id} with example value "42".
//
// Spec-derived paths are left untouched — their param names come from the spec.
func NormalizeTrafficPath(path string) (normalized string, params []ParameterMeta, examples []ParameterValue) {
	path = normalizePath(path)
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments))
	seen := map[string]int{} // placeholder name → count for dedup

	for _, seg := range segments {
		if seg == "" {
			out = append(out, seg)
			continue
		}
		if reUUID.MatchString(seg) || reNumeric.MatchString(seg) {
			name := dynamicParamName(seg, seen)
			out = append(out, "{"+name+"}")
			params = append(params, ParameterMeta{Name: name, In: "path", Type: paramType(seg)})
			examples = append(examples, ParameterValue{Name: name, In: "path", Example: seg})
		} else {
			out = append(out, seg)
		}
	}
	return strings.Join(out, "/"), params, examples
}

func dynamicParamName(_ string, seen map[string]int) string {
	seen["id"]++
	if seen["id"] == 1 {
		return "id"
	}
	return fmt.Sprintf("id%d", seen["id"])
}

func paramType(seg string) string {
	if reNumeric.MatchString(seg) {
		return "integer"
	}
	return "string"
}

func SortStringsStable(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}
