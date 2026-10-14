package interceptors

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestStreamLoggingInterceptor_SuccessPath ensures StreamLoggingInterceptor passes
// through the handler result on a successful stream.
func TestStreamLoggingInterceptor_SuccessPath(t *testing.T) {
	interceptor := StreamLoggingInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.AuditService/StreamAuditLogs"}

	called := false
	err := interceptor(nil, &fakeStream{ctx: context.Background()}, info,
		func(_ any, _ grpc.ServerStream) error {
			called = true
			return nil
		})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

// TestStreamLoggingInterceptor_ErrorPath ensures StreamLoggingInterceptor propagates
// handler errors.
func TestStreamLoggingInterceptor_ErrorPath(t *testing.T) {
	interceptor := StreamLoggingInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.AuditService/StreamAuditLogs"}
	handlerErr := errors.New("stream failure")

	err := interceptor(nil, &fakeStream{ctx: context.Background()}, info,
		func(_ any, _ grpc.ServerStream) error {
			return handlerErr
		})
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected original error to propagate, got %v", err)
	}
}

// TestClientUserAgent_PresentInMetadata returns the user-agent when present.
func TestClientUserAgent_PresentInMetadata(t *testing.T) {
	md := metadata.Pairs("user-agent", "grpc-go/1.60.0")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	got := ClientUserAgent(ctx)
	if got != "grpc-go/1.60.0" {
		t.Errorf("ClientUserAgent = %q, want %q", got, "grpc-go/1.60.0")
	}
}

// TestClientUserAgent_AbsentReturnsEmpty returns "" when user-agent is not set.
func TestClientUserAgent_AbsentReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	if got := ClientUserAgent(ctx); got != "" {
		t.Errorf("ClientUserAgent with no metadata = %q, want empty", got)
	}
}

// TestClientUserAgent_NoMetadataKey returns "" when metadata present but key missing.
func TestClientUserAgent_NoMetadataKey(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer tok")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if got := ClientUserAgent(ctx); got != "" {
		t.Errorf("ClientUserAgent without user-agent key = %q, want empty", got)
	}
}

// TestGetUserContextKey returns the package-level context key.
func TestGetUserContextKey(t *testing.T) {
	k := GetUserContextKey()
	if k != userContextKey {
		t.Errorf("GetUserContextKey() = %v, want %v", k, userContextKey)
	}
}

// TestWrappedServerStream_Context verifies wrappedServerStream.Context returns the
// injected context, not the underlying stream's context.
func TestWrappedServerStream_Context(t *testing.T) {
	type key struct{}
	inner := &fakeStream{ctx: context.Background()}
	injected := context.WithValue(context.Background(), key{}, "marker")
	ws := &wrappedServerStream{ServerStream: inner, ctx: injected}
	if v := ws.Context().Value(key{}); v != "marker" {
		t.Errorf("wrappedServerStream.Context() did not return injected context; got value %v", v)
	}
}

// TestActorKind_MachineType verifies ActorKind returns "machine_identity" for
// machine actor types.
func TestActorKind_MachineType(t *testing.T) {
	uc := &UserContext{ActorType: "machine_identity"}
	if got := uc.ActorKind(); got != "machine_identity" {
		t.Errorf("ActorKind() = %q, want %q", got, "machine_identity")
	}
}

// TestActorKind_UserType verifies ActorKind defaults to "user" for non-machine types.
func TestActorKind_UserType(t *testing.T) {
	uc := &UserContext{ActorType: ""}
	if got := uc.ActorKind(); got != "user" {
		t.Errorf("ActorKind() = %q, want %q", got, "user")
	}
}

// TestPrincipalID_Machine returns the MachineIdentityID for machine actors.
func TestPrincipalID_Machine(t *testing.T) {
	uc := &UserContext{ActorType: "machine_identity", MachineIdentityID: 42}
	if got := uc.PrincipalID(); got != 42 {
		t.Errorf("PrincipalID() = %d, want %d", got, 42)
	}
}

// TestPrincipalID_User returns the UserID for user actors.
func TestPrincipalID_User(t *testing.T) {
	uc := &UserContext{UserID: 7}
	if got := uc.PrincipalID(); got != 7 {
		t.Errorf("PrincipalID() = %d, want %d", got, 7)
	}
}

// fakeStream is a minimal grpc.ServerStream for stream-interceptor tests.
type fakeStream struct { // NOSONAR -- test-only struct; storing context.Context in a field is intentional here; godre:S8242
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeStream) Context() context.Context { return f.ctx }
