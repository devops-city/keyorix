package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetSecretScheduleAndLatestVersion (PERF-FIX-4) is composed from the mock's own
// GetSecretAccessSchedule and GetLatestSecretVersion, so a test that stubs those
// two (On("GetLatestSecretVersion", …)) drives the combined read unchanged: the
// schedule error is the call's error, the version error is LatestVersionErr.
func (m *MockStorage) GetSecretScheduleAndLatestVersion(ctx context.Context, secretNodeID uint) (*storage.SecretScheduleAndLatestVersion, error) {
	sched, err := m.GetSecretAccessSchedule(ctx, secretNodeID)
	if err != nil {
		return nil, err
	}
	version, verr := m.GetLatestSecretVersion(ctx, secretNodeID)
	return &storage.SecretScheduleAndLatestVersion{Schedule: sched, LatestVersion: version, LatestVersionErr: verr}, nil
}
