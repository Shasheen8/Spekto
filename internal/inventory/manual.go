package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type manualSeedDocument struct {
	Operations []manualSeedOperation `json:"operations" yaml:"operations"`
	Endpoints  []manualSeedOperation `json:"endpoints" yaml:"endpoints"`
	REST       []manualRESTSeed      `json:"rest" yaml:"rest"`
	GraphQL    []manualGraphQLSeed   `json:"graphql" yaml:"graphql"`
	GRPC       []manualGRPCSeed      `json:"grpc" yaml:"grpc"`
}

type manualSeedOperation struct {
	Protocol     string   `json:"protocol" yaml:"protocol"`
	Method       string   `json:"method" yaml:"method"`
	Path         string   `json:"path" yaml:"path"`
	Target       string   `json:"target" yaml:"target"`
	DisplayName  string   `json:"display_name" yaml:"display_name"`
	Tags         []string `json:"tags" yaml:"tags"`
	RequiresAuth *bool    `json:"requires_auth" yaml:"requires_auth"`
	AuthSchemes  []string `json:"auth_schemes" yaml:"auth_schemes"`
	RootKind     string   `json:"root_kind" yaml:"root_kind"`
	Name         string   `json:"name" yaml:"name"`
	Arguments    []string `json:"arguments" yaml:"arguments"`
	Package      string   `json:"package" yaml:"package"`
	Service      string   `json:"service" yaml:"service"`
	RPC          string   `json:"rpc" yaml:"rpc"`
	Streaming    string   `json:"streaming_mode" yaml:"streaming_mode"`
	RequestMsg   string   `json:"request_message" yaml:"request_message"`
	ResponseMsg  string   `json:"response_message" yaml:"response_message"`
}

type manualRESTSeed struct {
	Method       string   `json:"method" yaml:"method"`
	Path         string   `json:"path" yaml:"path"`
	Target       string   `json:"target" yaml:"target"`
	DisplayName  string   `json:"display_name" yaml:"display_name"`
	Tags         []string `json:"tags" yaml:"tags"`
	RequiresAuth *bool    `json:"requires_auth" yaml:"requires_auth"`
	AuthSchemes  []string `json:"auth_schemes" yaml:"auth_schemes"`
}

type manualGraphQLSeed struct {
	RootKind     string   `json:"root_kind" yaml:"root_kind"`
	Name         string   `json:"name" yaml:"name"`
	Arguments    []string `json:"arguments" yaml:"arguments"`
	Target       string   `json:"target" yaml:"target"`
	DisplayName  string   `json:"display_name" yaml:"display_name"`
	Tags         []string `json:"tags" yaml:"tags"`
	RequiresAuth *bool    `json:"requires_auth" yaml:"requires_auth"`
	AuthSchemes  []string `json:"auth_schemes" yaml:"auth_schemes"`
}

type manualGRPCSeed struct {
	Package      string   `json:"package" yaml:"package"`
	Service      string   `json:"service" yaml:"service"`
	RPC          string   `json:"rpc" yaml:"rpc"`
	Streaming    string   `json:"streaming_mode" yaml:"streaming_mode"`
	RequestMsg   string   `json:"request_message" yaml:"request_message"`
	ResponseMsg  string   `json:"response_message" yaml:"response_message"`
	Target       string   `json:"target" yaml:"target"`
	DisplayName  string   `json:"display_name" yaml:"display_name"`
	Tags         []string `json:"tags" yaml:"tags"`
	RequiresAuth *bool    `json:"requires_auth" yaml:"requires_auth"`
	AuthSchemes  []string `json:"auth_schemes" yaml:"auth_schemes"`
}

type ManualDocument struct {
	Operations []Operation
	SourceRef  SourceRef
}

func ParseManual(data []byte, source string) (*ManualDocument, error) {
	var doc manualSeedDocument
	if err := unmarshalManualData(data, &doc); err != nil {
		return nil, err
	}

	sourceRef := SourceRef{
		Type:         SourceManual,
		Location:     source,
		ParserFamily: "manual_seed",
		SupportLevel: SupportLevelFull,
	}

	var ops []Operation
	for _, item := range append(doc.Operations, doc.Endpoints...) {
		op, err := toManualOperation(item, sourceRef)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	for _, item := range doc.REST {
		op, err := toManualREST(item, sourceRef)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	for _, item := range doc.GraphQL {
		op, err := toManualGraphQL(item, sourceRef)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	for _, item := range doc.GRPC {
		op, err := toManualGRPC(item, sourceRef)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	if len(ops) == 0 {
		return nil, errors.New("manual seed document contains no operations")
	}

	merged := Merge(ops)
	return &ManualDocument{
		Operations: merged.Operations,
		SourceRef:  sourceRef,
	}, nil
}

func unmarshalManualData(data []byte, target *manualSeedDocument) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return errors.New("manual seed document is empty")
	}
	if strings.HasPrefix(trimmed, "[") {
		var ops []manualSeedOperation
		if err := json.Unmarshal(data, &ops); err != nil {
			return err
		}
		target.Operations = ops
		return nil
	}
	if manualLooksLikeJSON(trimmed) {
		return json.Unmarshal(data, target)
	}
	return yaml.Unmarshal(data, target)
}

func toManualOperation(item manualSeedOperation, sourceRef SourceRef) (Operation, error) {
	switch strings.ToLower(strings.TrimSpace(item.Protocol)) {
	case "rest", "http", "":
		return toManualREST(manualRESTSeed{
			Method:       item.Method,
			Path:         item.Path,
			Target:       item.Target,
			DisplayName:  item.DisplayName,
			Tags:         item.Tags,
			RequiresAuth: item.RequiresAuth,
			AuthSchemes:  item.AuthSchemes,
		}, sourceRef)
	case "graphql":
		return toManualGraphQL(manualGraphQLSeed{
			RootKind:     item.RootKind,
			Name:         item.Name,
			Arguments:    item.Arguments,
			Target:       item.Target,
			DisplayName:  item.DisplayName,
			Tags:         item.Tags,
			RequiresAuth: item.RequiresAuth,
			AuthSchemes:  item.AuthSchemes,
		}, sourceRef)
	case "grpc":
		return toManualGRPC(manualGRPCSeed{
			Package:      item.Package,
			Service:      item.Service,
			RPC:          item.RPC,
			Streaming:    item.Streaming,
			RequestMsg:   item.RequestMsg,
			ResponseMsg:  item.ResponseMsg,
			Target:       item.Target,
			DisplayName:  item.DisplayName,
			Tags:         item.Tags,
			RequiresAuth: item.RequiresAuth,
			AuthSchemes:  item.AuthSchemes,
		}, sourceRef)
	default:
		return Operation{}, fmt.Errorf("unsupported manual protocol %q", item.Protocol)
	}
}

func toManualREST(item manualRESTSeed, sourceRef SourceRef) (Operation, error) {
	method := strings.ToUpper(strings.TrimSpace(item.Method))
	if method == "" {
		return Operation{}, errors.New("manual rest seed is missing method")
	}
	if strings.TrimSpace(item.Path) == "" {
		return Operation{}, errors.New("manual rest seed is missing path")
	}
	op := NewRESTOperation(method, item.Path)
	op.SourceRefs = []SourceRef{sourceRef}
	op.Provenance = Provenance{ManuallySeeded: true}
	op.Confidence = 0.4
	op.Status = StatusNormalized
	op.DisplayName = displayNameOrLocator(item.DisplayName, op.Locator)
	op.Tags = SortStringsStable(item.Tags)
	if target := strings.TrimSpace(item.Target); target != "" {
		op.Targets = []string{target}
	}
	op.AuthHints = manualAuthHints(item.RequiresAuth, item.AuthSchemes)
	op.REST = &RESTDetails{
		Method:         method,
		NormalizedPath: normalizePath(item.Path),
		OriginalPath:   item.Path,
	}
	if len(op.Targets) > 0 {
		op.REST.ServerCandidates = append([]string(nil), op.Targets...)
	}
	return op, nil
}

func toManualGraphQL(item manualGraphQLSeed, sourceRef SourceRef) (Operation, error) {
	rootKind := strings.ToLower(strings.TrimSpace(item.RootKind))
	if rootKind == "" {
		rootKind = "query"
	}
	name := strings.TrimSpace(item.Name)
	if name == "" {
		return Operation{}, errors.New("manual graphql seed is missing name")
	}
	args := SortStringsStable(item.Arguments)
	signature := name
	if len(args) > 0 {
		signature = fmt.Sprintf("%s(%s)", name, strings.Join(args, ","))
	}
	locator := fmt.Sprintf("%s:%s", rootKind, signature)
	op := Operation{
		ID:          StableOperationID(ProtocolGraphQL, locator),
		Protocol:    ProtocolGraphQL,
		Family:      FamilyGraphQL,
		Locator:     locator,
		DisplayName: displayNameOrLocator(item.DisplayName, locator),
		SourceRefs:  []SourceRef{sourceRef},
		Provenance: Provenance{
			ManuallySeeded: true,
		},
		Confidence: 0.4,
		AuthHints:  manualAuthHints(item.RequiresAuth, item.AuthSchemes),
		SchemaRefs: SchemaRefs{
			Responses: map[string]string{},
		},
		Tags:   SortStringsStable(item.Tags),
		Status: StatusNormalized,
		GraphQL: &GraphQLDetails{
			RootKind:      rootKind,
			OperationName: name,
			ArgumentMap:   args,
		},
	}
	if target := strings.TrimSpace(item.Target); target != "" {
		op.Targets = []string{target}
	}
	return op, nil
}

func toManualGRPC(item manualGRPCSeed, sourceRef SourceRef) (Operation, error) {
	service := strings.TrimSpace(item.Service)
	rpc := strings.TrimSpace(item.RPC)
	if service == "" || rpc == "" {
		return Operation{}, errors.New("manual grpc seed must include service and rpc")
	}
	mode := strings.TrimSpace(item.Streaming)
	if mode == "" {
		mode = "unary"
	}
	op := Operation{
		ID:          StableOperationID(ProtocolGRPC, grpcLocator(item.Package, service, rpc)),
		Protocol:    ProtocolGRPC,
		Family:      FamilyGRPC,
		Locator:     grpcLocator(item.Package, service, rpc),
		DisplayName: displayNameOrLocator(item.DisplayName, grpcLocator(item.Package, service, rpc)),
		SourceRefs:  []SourceRef{sourceRef},
		Provenance: Provenance{
			ManuallySeeded: true,
		},
		Confidence: 0.4,
		AuthHints:  manualAuthHints(item.RequiresAuth, item.AuthSchemes),
		SchemaRefs: SchemaRefs{
			Request: item.RequestMsg,
			Responses: map[string]string{
				"grpc": item.ResponseMsg,
			},
		},
		Tags:   SortStringsStable(item.Tags),
		Status: StatusNormalized,
		GRPC: &GRPCDetails{
			Package:       strings.TrimSpace(item.Package),
			Service:       service,
			RPC:           rpc,
			StreamingMode: mode,
			RequestMsg:    strings.TrimSpace(item.RequestMsg),
			ResponseMsg:   strings.TrimSpace(item.ResponseMsg),
		},
	}
	if op.SchemaRefs.Responses["grpc"] == "" {
		delete(op.SchemaRefs.Responses, "grpc")
	}
	if target := strings.TrimSpace(item.Target); target != "" {
		op.Targets = []string{target}
	}
	return op, nil
}

func grpcLocator(pkg, service, rpc string) string {
	serviceName := strings.TrimSpace(service)
	if packageName := strings.TrimSpace(pkg); packageName != "" {
		serviceName = packageName + "." + serviceName
	}
	return serviceName + "/" + strings.TrimSpace(rpc)
}

func displayNameOrLocator(displayName, locator string) string {
	if strings.TrimSpace(displayName) == "" {
		return locator
	}
	return strings.TrimSpace(displayName)
}

func manualAuthHints(requiresAuth *bool, schemes []string) AuthHints {
	hints := AuthHints{
		RequiresAuth: AuthRequirementUnknown,
	}
	if requiresAuth != nil {
		if *requiresAuth {
			hints.RequiresAuth = AuthRequirementYes
		} else {
			hints.RequiresAuth = AuthRequirementNo
		}
		hints.AuthSource = AuthSourceOperator
	}
	for _, scheme := range schemes {
		switch strings.ToLower(strings.TrimSpace(scheme)) {
		case "bearer", "jwt":
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeBearer)
		case "basic":
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeBasic)
		case "cookie":
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeCookie)
		case "api_key_header", "apikey_header", "header":
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeAPIKeyHeader)
		case "api_key_query", "apikey_query", "query":
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeAPIKeyQuery)
		case "mtls":
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeMTLS)
		default:
			hints.AuthSchemes = append(hints.AuthSchemes, AuthSchemeUnknown)
		}
	}
	hints.AuthSchemes = uniqueAuthSchemes(hints.AuthSchemes)
	if hints.AuthSource == "" && len(hints.AuthSchemes) > 0 {
		hints.AuthSource = AuthSourceOperator
	}
	return hints
}

func manualLooksLikeJSON(value string) bool {
	return strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[")
}
