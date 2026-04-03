package grpc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Shasheen8/Spekto/internal/inventory"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestParseDescriptorSetExtractsOperations(t *testing.T) {
	set := &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			{
				Name:    proto.String("model.proto"),
				Package: proto.String("openai.models.v1"),
				Service: []*descriptorpb.ServiceDescriptorProto{
					{
						Name: proto.String("ModelService"),
						Method: []*descriptorpb.MethodDescriptorProto{
							{
								Name:            proto.String("GetModel"),
								InputType:       proto.String(".openai.models.v1.GetModelRequest"),
								OutputType:      proto.String(".openai.models.v1.Model"),
								ClientStreaming: proto.Bool(false),
								ServerStreaming: proto.Bool(false),
							},
							{
								Name:            proto.String("WatchModels"),
								InputType:       proto.String(".openai.models.v1.WatchModelsRequest"),
								OutputType:      proto.String(".openai.models.v1.Model"),
								ClientStreaming: proto.Bool(false),
								ServerStreaming: proto.Bool(true),
							},
						},
					},
				},
				MessageType: []*descriptorpb.DescriptorProto{
					{Name: proto.String("GetModelRequest")},
					{Name: proto.String("WatchModelsRequest")},
					{Name: proto.String("Model")},
				},
				Syntax: proto.String("proto3"),
			},
		},
	}
	data, err := proto.Marshal(set)
	if err != nil {
		t.Fatalf("proto.Marshal returned error: %v", err)
	}

	doc, err := ParseDescriptorSet(data, "model.pb")
	if err != nil {
		t.Fatalf("ParseDescriptorSet returned error: %v", err)
	}
	if doc.SourceKind != SourceKindDescriptorSet {
		t.Fatalf("unexpected source kind: %s", doc.SourceKind)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}

	unary := doc.Operations[0]
	stream := doc.Operations[1]
	if unary.Protocol != inventory.ProtocolGRPC {
		t.Fatalf("unexpected protocol: %s", unary.Protocol)
	}
	if unary.GRPC == nil {
		t.Fatalf("expected grpc details")
	}
	if unary.GRPC.StreamingMode != "unary" {
		t.Fatalf("unexpected unary streaming mode: %s", unary.GRPC.StreamingMode)
	}
	if stream.GRPC == nil || stream.GRPC.StreamingMode != "server_stream" {
		t.Fatalf("unexpected stream mode: %#v", stream.GRPC)
	}
	if unary.SchemaRefs.Request != "openai.models.v1.GetModelRequest" {
		t.Fatalf("unexpected request schema ref: %s", unary.SchemaRefs.Request)
	}
	if unary.SchemaRefs.Responses["grpc"] != "openai.models.v1.Model" {
		t.Fatalf("unexpected response schema ref: %s", unary.SchemaRefs.Responses["grpc"])
	}
}

func TestParseProtoFilesExtractsOperations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.proto")
	contents := `syntax = "proto3";
package spekto.grpc.v1;

service InventoryService {
  rpc ListModels(ListModelsRequest) returns (ListModelsResponse);
}

message ListModelsRequest {}
message ListModelsResponse {}
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("os.WriteFile returned error: %v", err)
	}

	doc, err := ParseProtoFiles([]string{dir}, []string{"inventory.proto"})
	if err != nil {
		t.Fatalf("ParseProtoFiles returned error: %v", err)
	}
	if doc.SourceKind != SourceKindProtoFiles {
		t.Fatalf("unexpected source kind: %s", doc.SourceKind)
	}
	if len(doc.Operations) != 1 {
		t.Fatalf("expected 1 operation, got %d", len(doc.Operations))
	}
	op := doc.Operations[0]
	if op.GRPC == nil {
		t.Fatalf("expected grpc details")
	}
	if op.GRPC.Package != "spekto.grpc.v1" {
		t.Fatalf("unexpected package: %s", op.GRPC.Package)
	}
	if op.GRPC.Service != "InventoryService" {
		t.Fatalf("unexpected service: %s", op.GRPC.Service)
	}
	if op.GRPC.RPC != "ListModels" {
		t.Fatalf("unexpected rpc: %s", op.GRPC.RPC)
	}
	if op.GRPC.StreamingMode != "unary" {
		t.Fatalf("unexpected stream mode: %s", op.GRPC.StreamingMode)
	}
	if op.Locator != "spekto.grpc.v1.InventoryService/ListModels" {
		t.Fatalf("unexpected locator: %s", op.Locator)
	}
}
