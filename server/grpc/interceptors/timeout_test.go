package interceptors

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// A slow unary handler is cut off at the configured deadline: the interceptor
// injects a timeout into the context, and a handler that outlives it gets
// DeadlineExceeded — the gRPC analogue of the HTTP request-timeout middleware.
func TestTimeoutInterceptor_CapsSlowHandler(t *testing.T) {
	interceptor := TimeoutInterceptor(50 * time.Millisecond)

	_, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"},
		func(ctx context.Context, _ any) (any, error) {
			_, ok := ctx.Deadline()
			require.True(t, ok, "the handler's context must carry the injected deadline")
			<-ctx.Done() // simulate a hung handler
			return nil, ctx.Err()
		})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// A handler that returns before the deadline is unaffected — the timeout only
// bounds the worst case, it does not add latency to normal calls.
func TestTimeoutInterceptor_FastHandlerUnaffected(t *testing.T) {
	interceptor := TimeoutInterceptor(time.Hour)

	resp, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"},
		func(context.Context, any) (any, error) { return "ok", nil })

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
}

// A client deadline tighter than the cap is preserved — context.WithTimeout only
// ever shortens, so the interceptor never extends a caller's own deadline.
func TestTimeoutInterceptor_PreservesShorterClientDeadline(t *testing.T) {
	interceptor := TimeoutInterceptor(time.Hour)
	clientCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	var handlerDeadline time.Time
	_, _ = interceptor(clientCtx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"},
		func(ctx context.Context, _ any) (any, error) {
			handlerDeadline, _ = ctx.Deadline()
			return "ok", nil
		})

	assert.WithinDuration(t, time.Now().Add(30*time.Millisecond), handlerDeadline, 25*time.Millisecond,
		"the tighter client deadline must win over the 1h cap")
}
