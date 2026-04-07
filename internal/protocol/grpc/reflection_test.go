package grpc

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	grpc_testing "google.golang.org/grpc/reflection/grpc_testing"
)

type searchServiceServer struct {
	grpc_testing.UnimplementedSearchServiceServer
}

func TestParseReflectionTargetExtractsOperations(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen returned error: %v", err)
	}
	defer lis.Close()

	server := grpc.NewServer()
	grpc_testing.RegisterSearchServiceServer(server, searchServiceServer{})
	reflection.Register(server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(lis)
	}()
	defer func() {
		server.Stop()
		<-errCh
	}()

	doc, err := ParseReflectionTarget(context.Background(), lis.Addr().String())
	if err != nil {
		t.Fatalf("ParseReflectionTarget returned error: %v", err)
	}
	if doc.SourceKind != SourceKindReflection {
		t.Fatalf("unexpected source kind: %s", doc.SourceKind)
	}
	if len(doc.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(doc.Operations))
	}

	var unaryFound bool
	var bidiFound bool
	for _, op := range doc.Operations {
		if op.GRPC == nil {
			t.Fatalf("expected grpc details")
		}
		switch op.GRPC.RPC {
		case "Search":
			unaryFound = true
			if op.GRPC.StreamingMode != "unary" {
				t.Fatalf("unexpected Search mode: %s", op.GRPC.StreamingMode)
			}
		case "StreamingSearch":
			bidiFound = true
			if op.GRPC.StreamingMode != "bidi_stream" {
				t.Fatalf("unexpected StreamingSearch mode: %s", op.GRPC.StreamingMode)
			}
		}
	}
	if !unaryFound || !bidiFound {
		t.Fatalf("expected both Search and StreamingSearch operations, got %#v", doc.Operations)
	}
}
