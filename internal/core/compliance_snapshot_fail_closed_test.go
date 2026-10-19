package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// #2834: a snapshot is an audit artefact. When any posture sub-rollup cannot be
// read, TakeComplianceSnapshot must fail closed -- error, names the unreadable
// area, and NO CompliancePostureSnapshot row -- instead of persisting partial
// counts and reporting success. GetCompliancePosture still returns the degraded
// posture to its caller but must not persist it either.
func TestTakeComplianceSnapshot_DegradedPostureFailsClosed_2834(t *testing.T) {
	t.Parallel()
	c, db := compliancePostureCoreDB(t)
	require.NoError(t, db.AutoMigrate(&models.CompliancePostureSnapshot{}))
	c.storage = failingLegalHoldStore(c.storage.(*store.LocalStorage))

	snap, err := c.TakeComplianceSnapshot(context.Background())
	require.Error(t, err)
	assert.Nil(t, snap)
	assert.True(t, errors.Is(err, ErrCompliancePostureDegraded), "got %v", err)
	assert.Contains(t, err.Error(), "legal_hold", "the error must name the unreadable area")
	assert.NotContains(t, err.Error(), "simulated db failure", "raw storage error text must not reach the caller")

	var n int64
	require.NoError(t, db.Model(&models.CompliancePostureSnapshot{}).Count(&n).Error)
	assert.Zero(t, n, "no snapshot row may be persisted when the posture is degraded")

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)
	require.True(t, p.Degraded)
	require.NoError(t, db.Model(&models.CompliancePostureSnapshot{}).Count(&n).Error)
	assert.Zero(t, n, "GetCompliancePosture must not persist a degraded posture either")
}
