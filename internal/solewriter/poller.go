package solewriter

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/solewriter/swstate"
)

// Settle waits until every transaction that was in progress when it was
// called has finished: a session that wrote a security table before this
// boot recorded itself as the holder (so the fence let it through) and
// commits only now. Run after InstallFence. On timeout the guard stays out of
// the authoritative state for good, with the reason, rather than failing the
// boot.
//
// It is a second, explicit barrier, not the only one: InstallFence already
// waits for such a writer through locks (on a first boot CREATE TRIGGER needs
// the table lock the writer holds; on a later boot the writer's own guard
// trigger holds the epoch row that InstallFence rewrites). So removing Settle
// does not turn TestSettle_WaitsForATransactionOlderThanTheBoot red; it keeps
// the ordering independent of how InstallFence happens to lock.
func (g *Guard) Settle(ctx context.Context) error {
	var snap string
	if err := g.conn.QueryRowContext(ctx, "SELECT pg_current_snapshot()::text").Scan(&snap); err != nil {
		return fmt.Errorf("single_writer: settle: %w", err)
	}
	deadline := time.Now().Add(g.opts.SettleTimeout)
	for {
		var done bool
		if err := g.conn.QueryRowContext(ctx,
			"SELECT coalesce(bool_and(pg_xact_status(x) <> 'in progress'), true) FROM pg_snapshot_xip($1::pg_snapshot) AS x", snap).Scan(&done); err != nil {
			return fmt.Errorf("single_writer: settle: %w", err)
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			g.leave(fmt.Sprintf("settle timed out after %s: a transaction older than this boot is still open (snapshot %s)", g.opts.SettleTimeout, snap))
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	// The first good poll moves the guard to authoritative.
	g.pollOnce(ctx)
	return nil
}

// Run polls until ctx ends or Close. It returns immediately; the poller runs
// in its own goroutine.
func (g *Guard) Run(ctx context.Context) {
	current.Store(g)
	// From here on the storage layer may skip a confirming read when the
	// guard vouches for it (swstate, local_folded_credential_memo.go).
	swstate.Set(g)
	go func() {
		defer close(g.done)
		t := time.NewTicker(PollInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-g.stop:
				return
			case <-t.C:
				g.pollOnce(ctx)
			}
		}
	}()
}

// pollOnce reads, in one statement on the holder connection: the backend pid,
// the proof that it holds the lock, the epoch and the fence fingerprint.
func (g *Guard) pollOnce(ctx context.Context) {
	pctx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	var (
		pid         int
		held        bool
		incarnation string
		epoch       int64
		fp          string
	)
	err := g.conn.QueryRowContext(pctx, `SELECT pg_backend_pid(), `+lockHeldExpr("pg_backend_pid()", "current_schema()")+`,
  e.incarnation, e.n, (`+fingerprintSQL+`)
FROM `+EpochTable+` e WHERE e.id = 1`).Scan(&pid, &held, &incarnation, &epoch, &fp)
	if err != nil {
		// A statement error on a live session (a timeout) only lets the
		// lease run out; a later good poll on the SAME backend proves the
		// lock was never released. A dead session means the lock is gone.
		pingCtx, pingCancel := context.WithTimeout(ctx, pollTimeout)
		pingErr := g.conn.PingContext(pingCtx)
		pingCancel()
		g.mu.Lock()
		defer g.mu.Unlock()
		g.lastErr = err.Error()
		if pingErr != nil && ctx.Err() == nil {
			g.leaveLocked(fmt.Sprintf("holder lock lost: the lock session is gone (%v)", err))
		}
		return
	}
	now := g.opts.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastErr = ""
	switch {
	case pid != g.pid || !held:
		g.leaveLocked(fmt.Sprintf("holder lock lost (connection backend pid %d, was %d, held=%v)", pid, g.pid, held))
		return
	case fp != g.fingerprint:
		g.leaveLocked("the write fence changed (a trigger or function was dropped, disabled or replaced)")
		return
	case incarnation != g.incarnation:
		g.leaveLocked("the write epoch was reinitialised by another process")
		return
	}
	reenter := false
	if g.state != StateAuthoritative && !g.permanent {
		reenter = g.state == StateConfirming
		g.state, g.reason = StateAuthoritative, ""
	}
	changed := epoch != g.epoch
	g.canaryLocked(changed)
	g.epoch = epoch
	g.lastGoodMono = now
	g.lastGoodWall = now.Round(0)
	if changed {
		if f := g.onEpochChange.Load(); f != nil {
			(*f)(epoch)
		}
	}
	if reenter {
		// Back from a lapse: nothing filled before it is trusted.
		g.tracker.Flush()
		if f := g.onReenter.Load(); f != nil {
			(*f)()
		}
	}
}

// canaryLocked accounts an epoch move to this process's own fenced commits.
// The epoch is bumped inside a writer's commit and the tracker counts the
// commit right after it returns, so a move is only called unattributed when
// the following poll still finds no commit (and none in flight) to explain it.
// Every in-process write is supposed to be seen by the tracker and every
// foreign one refused by the fence, so an unattributed move means one of the
// two missed a write: flush every entry and say so loudly.
func (g *Guard) canaryLocked(changed bool) {
	if g.tracker == nil {
		return
	}
	commits := g.tracker.commits.Load()
	explained := commits != g.lastCommits || g.tracker.Inflight() > 0
	g.lastCommits = commits
	switch {
	case changed && !explained:
		if g.unexplained {
			g.recordUnattributedLocked()
		}
		g.unexplained = true
	case g.unexplained && !explained:
		g.recordUnattributedLocked()
		g.unexplained = false
	default:
		g.unexplained = false
	}
}

func (g *Guard) recordUnattributedLocked() {
	g.unattributedBumps++
	g.tracker.Flush()
	logf("ERROR: the write epoch moved without a write this server accounts for (%d so far); every cache entry was flushed. "+
		"A write reached a security table outside the tracker (see internal/solewriter/tracker.go)", g.unattributedBumps)
}

// UnattributedBumps is the canary's count (tests: must stay 0).
func (g *Guard) UnattributedBumps() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.unattributedBumps
}

// Tracker is the guard's in-process write tracker.
func (g *Guard) Tracker() *Tracker { return g.tracker }

// leave moves the guard out of the authoritative state until restart.
func (g *Guard) leave(reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.leaveLocked(reason)
}

func (g *Guard) leaveLocked(reason string) {
	if g.permanent {
		return
	}
	g.permanent = true
	g.state, g.reason = StateConfirming, reason
	logf("confirming: %s; caches confirm every read until this server restarts", reason)
}

// Authoritative reports whether a cache may skip its confirming read right
// now: the state is authoritative and the last good poll is younger than the
// lease on BOTH the monotonic and the wall clock (a paused VM or a stopped
// process resumes with a stale monotonic reading on some platforms, but its
// wall clock has moved).
func (g *Guard) Authoritative() bool {
	if g == nil {
		return false
	}
	now := g.opts.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state != StateAuthoritative || g.lastGoodMono.IsZero() {
		return false
	}
	mono := now.Sub(g.lastGoodMono)
	wall := now.Round(0).Sub(g.lastGoodWall)
	return mono >= 0 && mono < LeaseDuration && wall > -LeaseDuration && wall < LeaseDuration
}

// BeginFill implements swstate.Authority.
func (g *Guard) BeginFill() swstate.Fill { return g.tracker.BeginFill() }

// Valid implements swstate.Authority: authoritative now, no fenced write in
// flight, and none finished since gen.
func (g *Guard) Valid(gen uint64) bool { return g.Authoritative() && g.tracker.Valid(gen) }

// Epoch is the last polled write epoch.
func (g *Guard) Epoch() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.epoch
}

// OnEpochChange registers f, called (from the poller) with each new epoch.
func (g *Guard) OnEpochChange(f func(int64)) { g.onEpochChange.Store(&f) }

// OnReenter registers f, called when the guard returns to authoritative after
// a lapse in which the lease ran out.
func (g *Guard) OnReenter(f func()) { g.onReenter.Store(&f) }

// Status is the guard's state for /system/info, the start-up line and the
// posture output.
type Status struct {
	Enabled       bool     `json:"enabled"`
	State         State    `json:"state"`
	Reason        string   `json:"reason,omitempty"`
	HolderPID     int      `json:"holder_pid"`
	Since         string   `json:"since"`
	FencedTables  []string `json:"fenced_tables"`
	Epoch         int64    `json:"epoch"`
	LastPollAgeMS int64    `json:"last_poll_age_ms"`
	LastPollError string   `json:"last_poll_error,omitempty"`
	// UnattributedBumps counts epoch moves no in-process write accounted for.
	UnattributedBumps int64  `json:"unattributed_bumps"`
	Authoritative     bool   `json:"authoritative"`
	Emergency         string `json:"emergency_sql"`
}

// EmergencySQL is the documented two-step for an emergency change made
// directly in the database while the server runs.
const EmergencySQL = "SELECT pg_terminate_backend(holder_pid) FROM " + HolderTable + "; then run the change. " +
	"The server stops trusting its caches within 1 s and does not resume until it is restarted."

// Status snapshots the guard.
func (g *Guard) Status() Status {
	auth := g.Authoritative()
	now := g.opts.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	st := Status{Enabled: true, State: g.state, Reason: g.reason, HolderPID: g.pid, Since: g.since.Format(time.RFC3339),
		FencedTables: FencedTableNames(), Epoch: g.epoch, LastPollError: g.lastErr, Authoritative: auth, Emergency: EmergencySQL,
		UnattributedBumps: g.unattributedBumps}
	if !g.lastGoodMono.IsZero() {
		st.LastPollAgeMS = now.Sub(g.lastGoodMono).Milliseconds()
	}
	if st.State == StateAuthoritative && !auth {
		st.State = StateConfirming
		st.Reason = "lease expired: no successful poll for over " + LeaseDuration.String()
	}
	return st
}

// StartupLine is the line the server logs once the guard is running.
func (g *Guard) StartupLine() string {
	st := g.Status()
	return fmt.Sprintf("single_writer: %s (lock held by backend pid %d; write fence on %d tables; epoch poll %s, lease %s). "+
		"Direct database writes to the security tables are refused while this server runs. Emergency: %s",
		st.State, st.HolderPID, len(st.FencedTables), PollInterval, LeaseDuration, EmergencySQL)
}
