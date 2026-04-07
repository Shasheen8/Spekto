package grpc

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/jhump/protoreflect/desc"
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func ParseReflectionTarget(ctx context.Context, target string) (*Document, error) {
	ctx, cancel := withTimeout(ctx, 10*time.Second)
	defer cancel()

	endpoint, dialOption, err := reflectionDialConfig(target)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.DialContext(ctx, endpoint, dialOption)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	client := grpcreflect.NewClientAuto(ctx, conn)
	defer client.Reset()

	services, err := client.ListServices()
	if err != nil {
		return nil, err
	}
	sort.Strings(services)

	doc := &Document{
		SourceKind: SourceKindReflection,
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     target,
			ParserFamily: "grpc_reflection",
			SupportLevel: inventory.SupportLevelFull,
		},
	}

	for _, serviceName := range services {
		if isReflectionService(serviceName) {
			continue
		}
		service, err := client.ResolveService(serviceName)
		if err != nil {
			doc.Warnings = append(doc.Warnings, err.Error())
			continue
		}
		for _, method := range service.GetMethods() {
			doc.Operations = append(doc.Operations, newReflectionOperation(service, method, doc.SourceRef))
		}
	}

	sort.Slice(doc.Operations, func(i, j int) bool {
		if doc.Operations[i].Locator == doc.Operations[j].Locator {
			return doc.Operations[i].ID < doc.Operations[j].ID
		}
		return doc.Operations[i].Locator < doc.Operations[j].Locator
	})

	return doc, nil
}

func newReflectionOperation(service *desc.ServiceDescriptor, method *desc.MethodDescriptor, sourceRef inventory.SourceRef) inventory.Operation {
	if service == nil || method == nil {
		return inventory.Operation{}
	}

	packageName := ""
	if file := service.GetFile(); file != nil {
		packageName = file.GetPackage()
	}
	return newGRPCOperationFields(
		packageName,
		service.GetName(),
		method.GetName(),
		trimDescriptorName(method.GetInputType()),
		trimDescriptorName(method.GetOutputType()),
		reflectionStreamingMode(method),
		sourceRef,
	)
}

func reflectionStreamingMode(method *desc.MethodDescriptor) string {
	switch {
	case method.IsClientStreaming() && method.IsServerStreaming():
		return "bidi_stream"
	case method.IsClientStreaming():
		return "client_stream"
	case method.IsServerStreaming():
		return "server_stream"
	default:
		return "unary"
	}
}

func trimDescriptorName(message *desc.MessageDescriptor) string {
	if message == nil {
		return ""
	}
	return strings.TrimPrefix(message.GetFullyQualifiedName(), ".")
}

func isReflectionService(serviceName string) bool {
	return strings.HasPrefix(serviceName, "grpc.reflection.")
}

func reflectionDialConfig(target string) (string, grpc.DialOption, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", nil, net.InvalidAddrError("empty reflection target")
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
	case scheme == "http":
		return endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	case scheme == "https":
		return endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})), nil
	case isLocalhost(host):
		return endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	default:
		return endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})), nil
	}
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

func withTimeout(ctx context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, duration)
}
