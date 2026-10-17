package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A grant used only to list a secret's versions (secret.versions_listed, which
// requires secrets.read) is exercised, not dormant: listing must count toward the
// read-tier and combined access activity, and must not count as write activity.
func TestAccessActivity_VersionsListedCountsAsReadTierUse(t *testing.T) {
	ctx := context.Background()
	ls := newAccessActivityStore(t)

	now := time.Now()
	insertAuditEvent(t, ls, 8, 60, "secret.versions_listed", now.Add(-time.Hour))

	read, err := ls.LastUserSecretReadActivity(ctx, 60, time.Time{})
	require.NoError(t, err)
	assert.Contains(t, read, uint(8), "a listing-only user must not look dormant on the read tier")

	all, err := ls.LastUserSecretActivity(ctx, 60, time.Time{})
	require.NoError(t, err)
	assert.Contains(t, all, uint(8))

	write, err := ls.LastUserSecretWriteActivity(ctx, 60, time.Time{})
	require.NoError(t, err)
	assert.NotContains(t, write, uint(8), "a listing is not write activity")
}
