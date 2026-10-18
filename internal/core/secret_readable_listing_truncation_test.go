// secret_readable_listing_truncation_test.go — follow-up item 2: the per-scope union
// bound must be LOUD, not silent.
//
// maxUnionPageSize bounds how many secrets ListReadableSecrets takes from each
// readable scope before merging. Its own comment claimed a pathological scope would
// "be truncated loudly-in-the-logs" — and nothing logged, and the response carried no
// signal, so the merged Total was simply short. That is the same defect class as
// #2780's confidently-wrong zero: a number that is quietly incomplete is worse than
// one that says it is incomplete.
//
// # Why there is an injectable bound
//
// The real bound is 100000. A test that exercised it honestly would seed 100001
// secrets — slow enough that nobody would run it, so the truncation path would stay
// unwatched, which is exactly how it came to be silent. c.unionPageSizeOverride
// lowers the bound for the test instead, so the path is driven at a fixture size that
// costs nothing. The override is unexported, defaults to 0 (= the real bound), and is
// set only here.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestListReadableSecrets_TruncationIsReportedNotSwallowed is the item-2 regression.
func TestListReadableSecrets_TruncationIsReportedNotSwallowed(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	seedReadableProject(t, db, 2, "beta", "b", 2)

	// Bound each scope at 4: project 1 (9 secrets) is truncated, project 2 (2) is not.
	c.unionPageSizeOverride = 4

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)

	assert.True(t, resp.Truncated,
		"a scope that held more secrets than the bound must mark the response truncated — otherwise "+
			"Total is silently a floor and the caller cannot tell")
	assert.Contains(t, resp.TruncatedReason, "project 1",
		"the reason must name the scope that was bounded, so an operator can act on it")
	assert.NotContains(t, resp.TruncatedReason, "project 2",
		"a scope that fit must not be reported as truncated")

	// The response still carries what it could: 4 from the bounded scope + 2 from the
	// scope that fit. The point is that it SAYS so, not that it is complete.
	assert.Equal(t, int64(6), resp.Total)
}

// TestListReadableSecrets_NotTruncatedWhenEveryScopeFits is the other direction, and
// it is the half that makes the test above mean something: without it, a bug that set
// Truncated unconditionally would pass.
func TestListReadableSecrets_NotTruncatedWhenEveryScopeFits(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 3)
	seedReadableProject(t, db, 2, "beta", "b", 2)

	c.unionPageSizeOverride = 10 // comfortably above both scopes

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.False(t, resp.Truncated, "every scope fit, so nothing was truncated")
	assert.Empty(t, resp.TruncatedReason)
	assert.Equal(t, int64(5), resp.Total)
}

// TestCountReadableSecrets_ReportsNonExactOnTruncation is the dashboard's half: the
// count must come back flagged, so GetDashboardStats can degrade rather than render a
// floor as a count.
func TestCountReadableSecrets_ReportsNonExactOnTruncation(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 9)

	c.unionPageSizeOverride = 4
	total, exact, err := c.CountReadableSecrets(ctx, 1, 1)
	require.NoError(t, err)
	assert.False(t, exact, "a bounded listing yields a floor, and the caller must be told")
	assert.Equal(t, int64(4), total, "the floor itself is still returned, for what it is worth")

	// And exact when it fits — the positive control.
	c.unionPageSizeOverride = 50
	total, exact, err = c.CountReadableSecrets(ctx, 1, 1)
	require.NoError(t, err)
	assert.True(t, exact)
	assert.Equal(t, int64(9), total)
}

// TestGetDashboardStats_DegradesOnTruncatedReadableCount closes the loop at the
// surface the user sees: TOTAL SECRETS must read as UNKNOWN, not as a number, when
// the underlying listing was bounded. DashboardStats.Degraded already means exactly
// that (see its doc comment); this wires the new signal into it.
func TestGetDashboardStats_DegradesOnTruncatedReadableCount(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	// The dashboard path needs these tables; readableListingFixture omits them
	// because the listing path does not touch them.
	require.NoError(t, db.AutoMigrate(&models.AuditEvent{}, &models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}))

	c.unionPageSizeOverride = 4
	stats, err := c.GetDashboardStats(ctx, 1, "reader", 1)
	require.NoError(t, err, "a bounded count must not abort the whole dashboard")

	assert.True(t, stats.Degraded,
		"a truncated readable-secret count makes TOTAL SECRETS a floor, which must read as incomplete")
	require.True(t, containsSubstring(stats.DegradedReasons, "total_secrets"),
		"the degrade must name total_secrets so an operator knows which tile is unreliable, got %v",
		stats.DegradedReasons)

	// Positive control: unbounded, the same fixture reports a clean snapshot.
	c.unionPageSizeOverride = 0
	clean, err := c.GetDashboardStats(ctx, 1, "reader", 1)
	require.NoError(t, err)
	assert.False(t, clean.Degraded,
		"nothing is bounded here, so the snapshot must not claim to be degraded; reasons: %v",
		clean.DegradedReasons)
	assert.Equal(t, int64(9), clean.TotalSecrets)
}

// TestListReadableSecrets_Tier2_StorageRowBoundIsReported is the coordinator's
// "Blocker 1/2" on #2874: the tier-2 union detected truncation only via
// resp.Total > len(resp.Secrets), which cannot fire when the STORAGE clamp
// (listingMaxRows) is what bites -- the per-scope page is then full and Total ==
// len(Secrets). The tests above only lower unionPageSizeOverride, i.e. drive the
// bound the storage clamp shadows. This one leaves the union bound at its real
// value and lowers the storage bound, with scoped (non-global) grants.
//
// RED before the fix: Truncated == false, Total == 3 (a floor shown as a count).
func TestListReadableSecrets_Tier2_StorageRowBoundIsReported(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	seedReadableProject(t, db, 2, "beta", "b", 2)

	c.listingMaxRowsOverride = 3 // union bound deliberately left at the real 100000

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.True(t, resp.Truncated,
		"the storage clamp cut project 1 from 9 to 3 secrets, so the union total is a FLOOR; got Truncated=false Total=%d", resp.Total)
	assert.Contains(t, resp.TruncatedReason, "project 1")
	assert.NotContains(t, resp.TruncatedReason, "project 2", "a scope that fit must not be reported")

	total, exact, err := c.CountReadableSecrets(ctx, 1, 1)
	require.NoError(t, err)
	assert.False(t, exact, "a count built from a storage-clamped scope is not exact (got total=%d)", total)
}

// Calibration for the above: storage bound not hit => not truncated, exact.
func TestListReadableSecrets_Tier2_StorageBoundNotHitIsExact(t *testing.T) {
	t.Parallel()
	c, db := readableListingFixture(t)
	ctx := context.Background()
	seedReadableProject(t, db, 1, "alpha", "a", 9)
	c.listingMaxRowsOverride = 50

	resp, err := c.ListReadableSecrets(ctx, 1, 1, &models.SecretListFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.False(t, resp.Truncated)
	assert.Equal(t, int64(9), resp.Total)
	_, exact, err := c.CountReadableSecrets(ctx, 1, 1)
	require.NoError(t, err)
	assert.True(t, exact)
}
