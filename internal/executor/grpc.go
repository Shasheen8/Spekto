package executor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/auth"
	"github.com/Shasheen8/Spekto/internal/config"
	"github.com/Shasheen8/Spekto/internal/inventory"
	oldproto "github.com/golang/protobuf/proto"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/dynamic"
	"github.com/jhump/protoreflect/dynamic/grpcdynamic"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpc_reflection_v1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
)

type grpcRuntime struct {
	conn    *grpc.ClientConn
	stub    grpcdynamic.Stub
	reflect *grpcreflect.Client
	methods map[string]*desc.MethodDescriptor
}

func ExecuteGRPC(ctx context.Context, target config.Target, operations []inventory.Operation, registry auth.Registry, policy HTTPPolicy, selectedAuthContexts []string) ([]Result, error) {
	limiter := newRateLimiter(policy.RateLimit)
	runtimes := map[string]*grpcRuntime{}
	defer closeGRPCRuntimes(runtimes)

	results := make([]Result, 0, len(operations))
	requestsUsed := 0

	for _, operation := range operations {
		authContextNames, skipResult, err := resolveAuthAssignments(operation, target, registry, selectedAuthContexts)
		if err != nil {
			return nil, err
		}
		if skipResult != nil {
			results = append(results, *skipResult)
			continue
		}
		for _, authContextName := range authAssignments(authContextNames) {
			if requestsUsed >= policy.RequestBudget {
				results = append(results, skippedProtocolResult(target, operation, authContextName, "skipped: request budget exceeded"))
				continue
			}
			requestsUsed++

			if limiter != nil {
				if err := limiter.Wait(ctx); err != nil {
					results = append(results, failedProtocolResult(target, operation, authContextName, "", err))
					continue
				}
			}

			runtime, err := grpcRuntimeForAuthContext(ctx, runtimes, target, registry, authContextName)
			if err != nil {
				results = append(results, failedProtocolResult(target, operation, authContextName, "", err))
				continue
			}
			results = append(results, executeGRPCOperation(ctx, runtime, target, operation, registry, authContextName, policy))
		}
	}

	return results, nil
}

func executeGRPCOperation(ctx context.Context, runtime *grpcRuntime, target config.Target, operation inventory.Operation, registry auth.Registry, authContextName string, policy HTTPPolicy) Result {
	result := Result{
		Protocol:        inventory.ProtocolGRPC,
		Target:          target.Name,
		OperationID:     operation.ID,
		Locator:         operation.Locator,
		DisplayName:     operation.DisplayName,
		AuthContextName: authContextName,
		StartedAt:       time.Now().UTC(),
		Evidence: Evidence{
			Request: RequestEvidence{
				GRPCMethod: operation.Locator,
			},
		},
	}

	if operation.GRPC == nil {
		result.Status = "failed"
		result.Error = "grpc operation is missing grpc details"
		return result
	}
	if operation.GRPC.StreamingMode != "unary" {
		result.Status = "skipped"
		result.Error = "skipped: streaming gRPC methods are not supported by the phase 2 executor"
		return result
	}

	method, err := runtime.method(operation)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	requestCtx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()

	if strings.TrimSpace(authContextName) != "" {
		authContext, ok := registry.Get(authContextName)
		if !ok {
			result.Status = "failed"
			result.Error = fmt.Sprintf("unknown auth context %q", authContextName)
			return result
		}
		metadataMap := authContext.ApplyGRPCMetadata(nil)
		result.Evidence.Request.Metadata = redactMetadata(metadataMap)
		requestCtx = metadata.NewOutgoingContext(requestCtx, metadata.New(metadataMap))
	}

	requestMessage := dynamic.NewMessage(method.GetInputType())
	start := time.Now()
	responseMessage, err := runtime.stub.InvokeRpc(requestCtx, method, requestMessage)
	result.Duration = time.Since(start)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		result.Evidence.Response.GRPCCode = status.Code(err).String()
		return result
	}

	body, truncated, marshalErr := marshalDynamicMessage(responseMessage, policy.MaxResponseBytes)
	if marshalErr != nil {
		result.Status = "failed"
		result.Error = marshalErr.Error()
		result.Evidence.Response.GRPCCode = codes.Internal.String()
		return result
	}

	result.Status = "succeeded"
	result.Evidence.Response.GRPCCode = codes.OK.String()
	result.Evidence.Response.Body = body
	result.Evidence.Response.Truncated = truncated
	return result
}

func grpcRuntimeForAuthContext(ctx context.Context, runtimes map[string]*grpcRuntime, target config.Target, registry auth.Registry, authContextName string) (*grpcRuntime, error) {
	if runtime, ok := runtimes[authContextName]; ok {
		return runtime, nil
	}

	authContext := auth.Context{}
	if strings.TrimSpace(authContextName) != "" {
		value, ok := registry.Get(authContextName)
		if !ok {
			return nil, fmt.Errorf("unknown auth context %q", authContextName)
		}
		authContext = value
	}

	endpoint, dialOption, err := grpcDialOption(target, authContext)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.DialContext(ctx, endpoint, dialOption)
	if err != nil {
		return nil, err
	}
	runtime := &grpcRuntime{
		conn:    conn,
		stub:    grpcdynamic.NewStub(conn),
		reflect: grpcreflect.NewClientV1Alpha(ctx, grpc_reflection_v1alpha.NewServerReflectionClient(conn)),
		methods: map[string]*desc.MethodDescriptor{},
	}
	runtimes[authContextName] = runtime
	return runtime, nil
}

func (r *grpcRuntime) method(operation inventory.Operation) (*desc.MethodDescriptor, error) {
	if method, ok := r.methods[operation.Locator]; ok {
		return method, nil
	}
	if operation.GRPC == nil {
		return nil, fmt.Errorf("grpc operation is missing grpc details")
	}

	serviceName := operation.GRPC.Service
	if operation.GRPC.Package != "" {
		serviceName = operation.GRPC.Package + "." + serviceName
	}
	service, err := r.reflect.ResolveService(serviceName)
	if err != nil {
		return nil, err
	}
	method := service.FindMethodByName(operation.GRPC.RPC)
	if method == nil {
		return nil, fmt.Errorf("grpc method %q not found on %q", operation.GRPC.RPC, serviceName)
	}
	r.methods[operation.Locator] = method
	return method, nil
}

func closeGRPCRuntimes(runtimes map[string]*grpcRuntime) {
	keys := make([]string, 0, len(runtimes))
	for key := range runtimes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		runtime := runtimes[key]
		if runtime.reflect != nil {
			runtime.reflect.Reset()
		}
		if runtime.conn != nil {
			_ = runtime.conn.Close()
		}
	}
}

func grpcDialOption(target config.Target, authContext auth.Context) (string, grpc.DialOption, error) {
	trimmed := strings.TrimSpace(target.Endpoint)
	if trimmed == "" {
		return "", nil, net.InvalidAddrError("empty grpc endpoint")
	}

	scheme := ""
	endpoint := trimmed
	if strings.Contains(trimmed, "://") {
		parsed, err := url.Parse(trimmed)
		if err != nil {
			return "", nil, err
		}
		scheme = strings.ToLower(parsed.Scheme)
		endpoint = parsed.Host
		if endpoint == "" {
			endpoint = parsed.Path
		}
	}

	host := endpoint
	if parsedHost, _, err := net.SplitHostPort(endpoint); err == nil {
		host = parsedHost
	}

	switch {
	case scheme == "http" || target.AllowPlaintext || isLocalhost(host):
		return endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	default:
		tlsConfig, err := authContext.TLSConfig()
		if err != nil {
			return "", nil, err
		}
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)), nil
	}
}

func marshalDynamicMessage(message oldproto.Message, maxBytes int64) ([]byte, bool, error) {
	if message == nil {
		return nil, false, nil
	}
	jsonMarshaler, ok := message.(interface{ MarshalJSON() ([]byte, error) })
	if !ok {
		return nil, false, fmt.Errorf("grpc response does not support json marshaling")
	}
	data, err := jsonMarshaler.MarshalJSON()
	if err != nil {
		return nil, false, err
	}
	if maxBytes <= 0 || int64(len(data)) <= maxBytes {
		return data, false, nil
	}
	return data[:maxBytes], true, nil
}

func redactMetadata(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if isSensitiveHeader(key) {
			out[key] = "[redacted]"
			continue
		}
		out[key] = values[key]
	}
	return out
}

func isLocalhost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
