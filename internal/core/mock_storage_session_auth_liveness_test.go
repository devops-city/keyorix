package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetSessionAuthLiveness (PERF-FIX-7) is composed from the mock's own
// GetUser and GetSessionByID (storage.ComposeSessionAuthLiveness, in the order
// the session cache-hit check used to call them), so a test that stubs those
// (On("GetUser"), On("GetSessionByID")) drives the combined read unchanged,
// errors included.
func (m *MockStorage) GetSessionAuthLiveness(ctx context.Context, userID, sessionID uint) (*storage.SessionAuthLiveness, error) {
	return storage.ComposeSessionAuthLiveness(ctx, m, userID, sessionID), nil
}
