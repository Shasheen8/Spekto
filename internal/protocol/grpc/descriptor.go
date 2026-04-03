package grpc

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"github.com/jhump/protoreflect/desc/protoparse"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

type SourceKind string

const (
	SourceKindDescriptorSet SourceKind = "descriptor_set"
	SourceKindProtoFiles    SourceKind = "proto_files"
)

type Document struct {
	SourceKind SourceKind
	Warnings   []string
	Operations []inventory.Operation
	SourceRef  inventory.SourceRef
}

func ParseDescriptorSetFile(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDescriptorSet(data, path)
}

func ParseDescriptorSet(data []byte, source string) (*Document, error) {
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, err
	}

	doc := &Document{
		SourceKind: SourceKindDescriptorSet,
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     source,
			ParserFamily: "grpc_descriptor_set",
			SupportLevel: inventory.SupportLevelFull,
		},
	}
	doc.Operations = extractOperations(files, doc.SourceRef)
	return doc, nil
}

func ParseProtoFiles(importPaths []string, files []string) (*Document, error) {
	parser := protoparse.Parser{
		ImportPaths: importPaths,
	}
	descs, err := parser.ParseFiles(files...)
	if err != nil {
		return nil, err
	}

	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]struct{}{}
	for _, desc := range descs {
		appendFileDescriptor(desc.AsFileDescriptorProto(), set, seen)
		deps := desc.GetDependencies()
		for _, dep := range deps {
			appendFileDescriptor(dep.AsFileDescriptorProto(), set, seen)
		}
	}

	fileset, err := protodesc.NewFiles(set)
	if err != nil {
		return nil, err
	}

	doc := &Document{
		SourceKind: SourceKindProtoFiles,
		SourceRef: inventory.SourceRef{
			Type:         inventory.SourceSpec,
			Location:     strings.Join(files, ","),
			ParserFamily: "grpc_proto_files",
			SupportLevel: inventory.SupportLevelFull,
		},
	}
	doc.Operations = extractOperations(fileset, doc.SourceRef)
	return doc, nil
}

func appendFileDescriptor(file *descriptorpb.FileDescriptorProto, set *descriptorpb.FileDescriptorSet, seen map[string]struct{}) {
	if file == nil || file.GetName() == "" {
		return
	}
	if _, ok := seen[file.GetName()]; ok {
		return
	}
	seen[file.GetName()] = struct{}{}
	set.File = append(set.File, file)
}

func extractOperations(files *protoregistry.Files, sourceRef inventory.SourceRef) []inventory.Operation {
	var ops []inventory.Operation
	files.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		filePackage := string(file.Package())
		services := file.Services()
		for i := 0; i < services.Len(); i++ {
			service := services.Get(i)
			for j := 0; j < service.Methods().Len(); j++ {
				method := service.Methods().Get(j)
				op := newGRPCOperation(filePackage, service, method, sourceRef)
				ops = append(ops, op)
			}
		}
		return true
	})
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].Locator == ops[j].Locator {
			return ops[i].ID < ops[j].ID
		}
		return ops[i].Locator < ops[j].Locator
	})
	return ops
}

func newGRPCOperation(pkg string, service protoreflect.ServiceDescriptor, method protoreflect.MethodDescriptor, sourceRef inventory.SourceRef) inventory.Operation {
	serviceName := string(service.Name())
	fullServiceName := serviceName
	if pkg != "" {
		fullServiceName = pkg + "." + serviceName
	}
	locator := fullServiceName + "/" + string(method.Name())

	inputName := fullName(method.Input())
	outputName := fullName(method.Output())
	responseMap := map[string]string{}
	if outputName != "" {
		responseMap["grpc"] = outputName
	}

	return inventory.Operation{
		ID:          inventory.StableOperationID(inventory.ProtocolGRPC, locator),
		Protocol:    inventory.ProtocolGRPC,
		Family:      inventory.FamilyGRPC,
		Locator:     locator,
		DisplayName: locator,
		SourceRefs:  []inventory.SourceRef{sourceRef},
		Provenance: inventory.Provenance{
			Specified: true,
		},
		Confidence: 0.8,
		AuthHints: inventory.AuthHints{
			RequiresAuth: inventory.AuthRequirementUnknown,
		},
		SchemaRefs: inventory.SchemaRefs{
			Request:   inputName,
			Responses: responseMap,
		},
		Status: inventory.StatusNormalized,
		GRPC: &inventory.GRPCDetails{
			Package:       pkg,
			Service:       serviceName,
			RPC:           string(method.Name()),
			StreamingMode: streamingMode(method),
			RequestMsg:    inputName,
			ResponseMsg:   outputName,
		},
	}
}

func fullName(desc protoreflect.Descriptor) string {
	if desc == nil {
		return ""
	}
	return string(desc.FullName())
}

func streamingMode(method protoreflect.MethodDescriptor) string {
	switch {
	case method.IsStreamingClient() && method.IsStreamingServer():
		return "bidi_stream"
	case method.IsStreamingClient():
		return "client_stream"
	case method.IsStreamingServer():
		return "server_stream"
	default:
		return "unary"
	}
}

func DebugString(op inventory.Operation) string {
	if op.GRPC == nil {
		return op.Locator
	}
	return fmt.Sprintf("%s (%s)", op.Locator, op.GRPC.StreamingMode)
}
