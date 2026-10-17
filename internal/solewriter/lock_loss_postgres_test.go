package solewriter

// lock_loss_postgres_test.go — a lost holder lock closes Guard.Lost, so the
// server stops instead of running beside the next single writer
// (LOCKLOSS-SESSION-1, INV-STORAGE-session-advisory-lock-loss). Same harness as
// solewriter_postgres_test.go.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGuard_KilledHolderBackend_ClosesLost: while the holder session lives
// Lost stays open (and so across ordinary polls); after a
// pg_terminate_backend of the holder session a second server can take the
// lock at once, and Lost must close within a poll or two so the first one
// shuts down. A fence or epoch change (the guard leaves authoritative, the
// lock is still held) does not close it.
func TestGuard_KilledHolderBackend_ClosesLost(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)

	select {
	case <-g.Lost():
		t.Fatal("Lost closed while the holder session was alive")
	case <-time.After(4 * PollInterval):
	}

	var terminated bool
	require.NoError(t, w.foreign.Raw("SELECT pg_terminate_backend(?)", g.PID()).Scan(&terminated).Error)
	require.True(t, terminated)

	// The lock is free: another single-writer server could start now.
	second, err := Start(context.Background(), w.cfg, Options{LockWait: 2 * time.Second, SkipPresenceCensus: true})
	require.NoError(t, err, "a second server could not take the released holder lock: the test proves nothing")
	t.Cleanup(second.Close)

	select {
	case <-g.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the holder lock was lost (backend terminated) and another server took it, but Guard.Lost never closed: two single writers run")
	}
	require.Equal(t, StateConfirming, g.Status().State)
}

// TestGuard_FenceChangeDoesNotCloseLost: leaving the authoritative state for a
// reason other than a lost lock keeps the server running (confirming caches).
func TestGuard_FenceChangeDoesNotCloseLost(t *testing.T) {
	w := newSWWorld(t)
	g := w.start(Options{})
	require.Eventually(t, g.Authoritative, 2*time.Second, 20*time.Millisecond)
	g.leave("test: the write fence changed")
	time.Sleep(4 * PollInterval)
	select {
	case <-g.Lost():
		t.Fatal("Lost closed although the holder lock is still held")
	default:
	}
	var nilGuard *Guard
	require.Nil(t, nilGuard.Lost())
}
