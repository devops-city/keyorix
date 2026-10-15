package http

// single_writer_authoritative_test.go — storage.database.single_writer's
// authoritative machine-token read path (local_folded_credential_memo.go),
// through the real router and the production storage factory, PostgreSQL only.
//
//   - a warm read runs no confirming statement at all;
//   - every way a machine token stops being good, done through this server
//     (core calls or its own pool, both seen by the tracker), denies on the very
//     next request, exactly as a cold replica answers;
//   - a revocation racing a stream of reads: no read that starts after the
//     revoking call returned succeeds;
//   - when the guard stops vouching (its lock is gone), reads confirm again.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/solewriter"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	customMiddleware "github.com/keyorixhq/keyorix/server/middleware"
)

// newSWAuthWorld is newFCWorld with a single-writer guard: Start before any
// pool opens, then the fence, settle and the poller once the schema exists.
func newSWAuthWorld(t *testing.T, replicas int) (*svWorld, *solewriter.Guard) {
	t.Helper()
	cfg := svStorageConfig(t, "postgres")
	t.Cleanup(config.ClearSoleWriterSessionTagForTest)
	g, err := solewriter.Start(context.Background(), cfg, solewriter.Options{SkipPresenceCensus: true, LockWait: 2 * time.Second})
	require.NoError(t, err)
	t.Cleanup(g.Close)
	customMiddleware.ResetCredentialReadFoldMarksForTest()
	t.Cleanup(customMiddleware.ResetCredentialReadFoldMarksForTest)
	w := newSVWorldFromConfig(t, "postgres", replicas, cfg)
	require.NoError(t, g.InstallFence(context.Background()))
	require.NoError(t, g.Settle(context.Background()))
	g.Run(context.Background())
	require.Eventually(t, g.Authoritative, 2*time.Second, 10*time.Millisecond)
	return w, g
}

// swConfirmingStatement reports whether stmts contain the confirming
// statement (the folded read) or any other read of the credential or node.
func swConfirmingStatement(stmts []string) bool {
	for _, s := range stmts {
		if strings.Contains(s, "machine_identity_credentials") || strings.Contains(s, "secret_nodes n") {
			return true
		}
	}
	return false
}

func TestSingleWriter_WarmMachineReadRunsNoConfirmingStatement(t *testing.T) {
	w, g := newSWAuthWorld(t, 1)
	sec, v1 := w.newSecret(t, nil)
	fcWarm(t, w, w.a, sec, v1, true) // the folded statement ran once: memoized
	var got string
	stmts := fcStatements(w.a, func() { got = fcRead(w.a, w.tokens["machine"], sec.ID) })
	require.Equal(t, "200 "+v1, got)
	require.False(t, swConfirmingStatement(stmts), "an authoritative warm read must run no confirming statement; ran:\n%s", strings.Join(stmts, "\n"))
	require.Zero(t, g.UnattributedBumps())
}

// TestSingleWriter_ServerPathRevocationIsImmediate: warm and memoized on A,
// ended through A, the next read on A answers as a cold replica C does.
// Red with the tracker's generation bump removed (the memo keeps serving).
func TestSingleWriter_ServerPathRevocationIsImmediate(t *testing.T) {
	cases := append(fcCredentialCases(),
		// The per-site token cache is not evicted on this path: only the
		// tracker and the memo's validity check deny the next read (F5).
		fcCase{"token-revoked-on-server-pool", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", cred.ID).Error)
		}},
		fcCase{"rotation", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			w.rotate(t, w.a.c, sec, "sw-rotated")
		}},
		fcCase{"node-suspended", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", sec.ID).Error)
		}},
		fcCase{"node-deleted", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now(), sec.ID).Error)
		}},
		fcCase{"schedule-closed", func(t *testing.T, w *svWorld, sec *models.SecretNode, _ models.MachineIdentityCredential) {
			start, end := svDenyHours(time.Now().UTC().Hour())
			w.putSchedule(t, w.a.db, sec.ID, "*", start, end, "UTC")
		}},
		fcCase{"machine-role-removed", func(t *testing.T, w *svWorld, _ *models.SecretNode, cred models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("DELETE FROM machine_identity_roles WHERE machine_identity_id = ?", cred.MachineIdentityID).Error)
		}},
		fcCase{"role-permission-removed", func(t *testing.T, w *svWorld, _ *models.SecretNode, _ models.MachineIdentityCredential) {
			var role models.Role
			require.NoError(t, w.a.db.Where("name = ?", "sv-reader").First(&role).Error)
			require.NoError(t, w.a.db.Exec("DELETE FROM role_permissions WHERE role_id = ?", role.ID).Error)
		}},
		fcCase{"project-deleted", func(t *testing.T, w *svWorld, _ *models.SecretNode, _ models.MachineIdentityCredential) {
			require.NoError(t, w.a.db.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", time.Now(), w.projID).Error)
		}},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svAvoidHourBoundary(t)
			w, g := newSWAuthWorld(t, 3)
			sec, v1 := w.newSecret(t, nil)
			fcWarm(t, w, w.a, sec, v1, true)
			tok := w.tokens["machine"]
			stmts := fcStatements(w.a, func() { require.Equal(t, "200 "+v1, fcRead(w.a, tok, sec.ID)) })
			require.False(t, swConfirmingStatement(stmts), "precondition: the warm read is served from the memo")

			tc.end(t, w, sec, fcMachineCred(t, w))

			got := fcRead(w.a, tok, sec.ID)
			require.NotEqual(t, "200 "+v1, got, "%s through this server must take effect on the very next request", tc.name)
			require.Equal(t, fcRead(w.c, tok, sec.ID), got, "the authoritative replica must answer as a cold one after %s", tc.name)
			require.Zero(t, g.UnattributedBumps())
		})
	}
}

// TestSingleWriter_RevocationRacingReaders: readers hammer a memoized secret
// while the token is revoked through core; no read that STARTED after
// RevokeMachineToken returned may succeed. RevokeMachineToken also evicts the
// per-site token cache, so this one stays green without the tracker
// (REVIEW-SINGLE-WRITER-1 F5); ..._ThroughTheServerPool below does not.
func TestSingleWriter_RevocationRacingReaders(t *testing.T) {
	swRevocationRace(t, func(w *svWorld, cred models.MachineIdentityCredential) {
		_, err := w.a.c.RevokeMachineToken(context.Background(), w.projID, cred.MachineIdentityID, cred.ID, w.adminID)
		require.NoError(t, err)
	})
}

// TestSingleWriter_RevocationRacingReaders_ThroughTheServerPool: the same
// race, revoked by a statement on the server's own pool, which evicts no
// per-site cache. Only the tracker's generation and the memo's validity check
// stand between the readers and the memoized answer, so this is red with
// either removed (M10, M11).
func TestSingleWriter_RevocationRacingReaders_ThroughTheServerPool(t *testing.T) {
	swRevocationRace(t, func(w *svWorld, cred models.MachineIdentityCredential) {
		require.NoError(t, w.a.db.Exec("UPDATE machine_identity_credentials SET revoked = true WHERE id = ?", cred.ID).Error)
	})
}

func swRevocationRace(t *testing.T, revoke func(*svWorld, models.MachineIdentityCredential)) {
	w, _ := newSWAuthWorld(t, 1)
	sec, v1 := w.newSecret(t, nil)
	fcWarm(t, w, w.a, sec, v1, true)
	tok := w.tokens["machine"]
	cred := fcMachineCred(t, w)
	stmts := fcStatements(w.a, func() { require.Equal(t, "200 "+v1, fcRead(w.a, tok, sec.ID)) })
	require.False(t, swConfirmingStatement(stmts), "precondition: the readers start on memo hits")

	type obs struct {
		start time.Time
		got   string
	}
	var (
		mu   sync.Mutex
		seen []obs
		stop = make(chan struct{})
		wg   sync.WaitGroup
	)
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				start := time.Now()
				got := fcRead(w.a, tok, sec.ID)
				mu.Lock()
				seen = append(seen, obs{start, got})
				mu.Unlock()
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	revoke(w, cred)
	revokedAt := time.Now()
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	after := 0
	for _, o := range seen {
		if o.start.After(revokedAt) {
			after++
			require.NotEqual(t, "200 "+v1, o.got, "a read that started after the revocation returned succeeded")
		}
	}
	require.Positive(t, after, "harness: some reads must start after the revocation")
	t.Logf("%d reads, %d started after the revocation returned, none succeeded", len(seen), after)
}

// TestSingleWriter_LostLockConfirmsAgain: once the guard stops vouching, the
// memo is not used and the confirming statement runs again.
func TestSingleWriter_LostLockConfirmsAgain(t *testing.T) {
	w, g := newSWAuthWorld(t, 1)
	sec, v1 := w.newSecret(t, nil)
	fcWarm(t, w, w.a, sec, v1, true)
	g.Close()
	require.Eventually(t, func() bool { return !g.Authoritative() }, 3*time.Second, 20*time.Millisecond)
	var got string
	stmts := fcStatements(w.a, func() { got = fcRead(w.a, w.tokens["machine"], sec.ID) })
	require.Equal(t, "200 "+v1, got)
	require.True(t, swConfirmingStatement(stmts), "without the guard's word the read must confirm against the database")
}

// TestSingleWriter_ExpiryByTimeAloneIsSeenOnAMemoHit: no write happens; the
// token simply reaches its expires_at while its row sits in the memo. The
// memo returns the row, and CurrentMachineTokenRestriction judges expires_at
// against the request's clock, so the read is denied.
func TestSingleWriter_ExpiryByTimeAloneIsSeenOnAMemoHit(t *testing.T) {
	w, _ := newSWAuthWorld(t, 1)
	cred := fcMachineCred(t, w)
	soon := time.Now().Add(2 * time.Second)
	cred.ExpiresAt = &soon
	require.NoError(t, w.a.db.Save(&cred).Error) // before warming: the memo holds this row
	sec, v1 := w.newSecret(t, nil)
	fcWarm(t, w, w.a, sec, v1, true)
	tok := w.tokens["machine"]
	stmts := fcStatements(w.a, func() { require.Equal(t, "200 "+v1, fcRead(w.a, tok, sec.ID)) })
	require.False(t, swConfirmingStatement(stmts), "precondition: served from the memo")
	time.Sleep(time.Until(soon) + 200*time.Millisecond)
	require.NotEqual(t, "200 "+v1, fcRead(w.a, tok, sec.ID), "an expired token must be denied even when its row comes from the memo")
}
