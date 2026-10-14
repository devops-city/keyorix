package interceptors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func runWriteContention(t *testing.T, h grpc.UnaryHandler) (any, error) {
	t.Helper()
	return WriteContentionInterceptor()(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/keyorix.Test/Write"}, h)
}

func TestWriteContentionInterceptor_MapsToUnavailable(t *testing.T) {
	cases := map[string]grpc.UnaryHandler{
		"internal status after a gate timeout": func(ctx context.Context, _ any) (any, error) {
			corestorage.NoteWriteContention(ctx)
			return nil, status.Error(codes.Internal, "failed to create secret: sqlite: timed out waiting for the database write lock")
		},
		"unknown error after a gate timeout": func(ctx context.Context, _ any) (any, error) {
			corestorage.NoteWriteContention(ctx)
			return nil, errors.New("storage failure")
		},
		"bare wrapped sentinel": func(context.Context, any) (any, error) {
			return nil, fmt.Errorf("create: %w", corestorage.ErrSQLiteWriteContention)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			resp, err := runWriteContention(t, h)
			require.Error(t, err)
			assert.Nil(t, resp)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Unavailable, st.Code())
			assert.Equal(t, "The service is temporarily busy. Please retry shortly.", st.Message(), "fixed message, no internal detail")
		})
	}
}

func TestWriteContentionInterceptor_LeavesOtherOutcomesAlone(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		resp, err := runWriteContention(t, func(ctx context.Context, _ any) (any, error) {
			corestorage.NoteWriteContention(ctx)
			return "ok", nil
		})
		require.NoError(t, err)
		assert.Equal(t, "ok", resp)
	})
	t.Run("internal with no gate timeout", func(t *testing.T) {
		_, err := runWriteContention(t, func(context.Context, any) (any, error) {
			return nil, status.Error(codes.Internal, "boom")
		})
		assert.Equal(t, codes.Internal, status.Code(err))
	})
	for _, c := range []codes.Code{codes.NotFound, codes.PermissionDenied, codes.FailedPrecondition, codes.Unauthenticated} {
		t.Run(c.String()+" after a swallowed gate timeout", func(t *testing.T) {
			_, err := runWriteContention(t, func(ctx context.Context, _ any) (any, error) {
				corestorage.NoteWriteContention(ctx)
				return nil, status.Error(c, "chosen by the service")
			})
			assert.Equal(t, c, status.Code(err), "a status the service chose is never rewritten")
		})
	}
}
