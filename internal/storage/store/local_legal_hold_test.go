package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLegalHoldStore(t *testing.T) *LocalStorage {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(&models.LegalHold{}))
	// The production migration (storage.ensureLegalHoldActiveIndex) creates this;
	// replicate it for the test DB, per the TestGroupSoftDelete_NameReuse convention.
	require.NoError(t, db.Exec(
		"CREATE UNIQUE INDEX uniq_legal_holds_active ON legal_holds (released) WHERE released = false",
	).Error)
	return NewLocalStorage(db)
}

// The partial unique index rejects a second concurrent un-released row (#305), and
// the rejection surfaces as the ErrLegalHoldAlreadyActive sentinel — not a generic
// storage error — so callers can map it to a client error.
func TestLegalHold_ActiveIndexRejectsDuplicate(t *testing.T) {
	ls := newLegalHoldStore(t)
	ctx := context.Background()

	_, err := ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "first", PlacedBy: 1})
	require.NoError(t, err)

	_, err = ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "second", PlacedBy: 2})
	require.Error(t, err)
	assert.True(t, errors.Is(err, corestorage.ErrLegalHoldAlreadyActive),
		"a duplicate active hold must surface as ErrLegalHoldAlreadyActive, not a generic storage error")

	var count int64
	require.NoError(t, ls.db.Model(&models.LegalHold{}).Where("released = ?", false).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the DB must contain exactly one active hold row")
}

// A released hold does not block a new one — the index only constrains released =
// false rows.
func TestLegalHold_ActiveIndexAllowsNewHoldAfterRelease(t *testing.T) {
	ls := newLegalHoldStore(t)
	ctx := context.Background()

	first, err := ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "first", PlacedBy: 1})
	require.NoError(t, err)

	first.Released = true
	require.NoError(t, ls.UpdateLegalHold(ctx, first))

	_, err = ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "second", PlacedBy: 1})
	require.NoError(t, err, "a new hold is allowed once the prior one is released")
}

// TestConcurrency_CreateLegalHold_OnlyOneWins drives many concurrent CreateLegalHold
// calls at the raw storage layer (bypassing core.PlaceLegalHold's own pre-check
// entirely) and asserts the DB-level unique index still allows exactly one to
// succeed. This is the storage-layer backstop for the TOCTOU race in
// core.PlaceLegalHold (#305): even if the application-level check-then-insert races,
// the constraint here is what actually prevents two active rows from existing.
func TestConcurrency_CreateLegalHold_OnlyOneWins(t *testing.T) {
	ls := newLegalHoldStore(t)
	ctx := context.Background()

	const callers = 32
	var succeeded atomic.Int64
	unexpected := make(chan error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			_, cerr := ls.CreateLegalHold(ctx, &models.LegalHold{Reason: "concurrent", PlacedBy: uint(n)})
			if cerr == nil {
				succeeded.Add(1)
				return
			}
			if !errors.Is(cerr, corestorage.ErrLegalHoldAlreadyActive) {
				unexpected <- cerr
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(unexpected)
	for e := range unexpected {
		require.NoError(t, e)
	}

	assert.Equal(t, int64(1), succeeded.Load(), "exactly one concurrent CreateLegalHold call may succeed")

	var count int64
	require.NoError(t, ls.db.Model(&models.LegalHold{}).Where("released = ?", false).Count(&count).Error)
	assert.Equal(t, int64(1), count, "the DB must contain exactly one active hold row, never a duplicate")
}
