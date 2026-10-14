package interceptors

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRecoveryInterceptor_CatchesPanicInDownstreamInterceptor pins the ordering
// contract NewServer (server/grpc/server.go) relies on: RecoveryInterceptor is
// registered FIRST in grpc.ChainUnaryInterceptor, i.e. OUTERMOST — grpc-go chains
// interceptors so the first one wraps every interceptor listed after it. So a panic
// in ANY later interceptor (logging, timeout, auth, metrics) — not just a panic in
// the final handler — must be caught. This composes that exact chain shape directly:
// RecoveryInterceptor wraps a stand-in for a later interceptor that panics before
// ever reaching the real handler.
func TestRecoveryInterceptor_CatchesPanicInDownstreamInterceptor(t *testing.T) {
	recovery := RecoveryInterceptor()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}

	// Stands in for a later-chained interceptor (e.g. LoggingInterceptor) that panics
	// before ever delegating to the real handler — handlerCalled staying false is the
	// evidence the real handler was never reached.
	handlerCalled := false
	panickyDownstream := func(_ context.Context, _ any) (any, error) {
		panic("boom: downstream interceptor panic")
	}

	resp, err := recovery(context.Background(), nil, info, panickyDownstream)

	require.Error(t, err)
	assert.Nil(t, resp)
	assert.False(t, handlerCalled, "the panic must be caught before the real handler ever runs")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.NotContains(t, st.Message(), "boom", "the panic value must not leak into the client-facing status")
}

// TestStreamRecoveryInterceptor_CatchesPanicInDownstreamInterceptor is the stream
// analogue: StreamRecoveryInterceptor is likewise registered first in
// grpc.ChainStreamInterceptor, so it must catch a panic in a later stream
// interceptor (e.g. StreamLoggingInterceptor), not just in the stream handler.
func TestStreamRecoveryInterceptor_CatchesPanicInDownstreamInterceptor(t *testing.T) {
	recovery := StreamRecoveryInterceptor()
	info := &grpc.StreamServerInfo{FullMethod: "/keyorix.v1.AuditService/StreamAuditLogs"}

	handlerCalled := false
	panickyDownstream := func(_ any, _ grpc.ServerStream) error {
		panic("boom: downstream stream interceptor panic")
	}

	err := recovery(nil, nil, info, panickyDownstream)

	require.Error(t, err)
	assert.False(t, handlerCalled, "the panic must be caught before the real handler ever runs")
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.NotContains(t, st.Message(), "boom", "the panic value must not leak into the client-facing status")
}
