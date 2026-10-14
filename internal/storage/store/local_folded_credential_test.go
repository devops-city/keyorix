package store

// PERF-LEVER2: the machine-credential re-check reads the node stamp, the
// machine's roles and the schedule/version state of one secret in the same
// statement when the request asked for it (storage.ReadPathPrefetch with a
// fold target). The credential comes back field for field as the plain
// statement returns it, the node answers field for field as the node-stamp
// statement returns them, and they are only ever taken by GetSecret for that
// secret and that machine.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type foldWorld struct {
	prefetchWorld
	hash string
}

func newFoldWorld(t *testing.T, backend string) foldWorld {
	return newFoldWorldWith(t, backend, nil)
}

func newFoldWorldWith(t *testing.T, backend string, prep func(*LocalStorage)) foldWorld {
	t.Helper()
	w := newPrefetchWorldWith(t, backend, prep)
	require.NoError(t, w.ls.db.AutoMigrate(&models.MachineIdentityCredential{}))
	hash := w.name("fold-hash")
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, w.ls.db.Create(&models.MachineIdentityCredential{
		MachineIdentityID: w.machine, Name: w.name("cred"), TokenHash: hash, TokenPrefix: "kx_machine_x",
		AllowedCIDRs: `["192.0.2.0/24"]`, ExpiresAt: &exp, CreatedAt: time.Now(),
	}).Error)
	return foldWorld{prefetchWorld: w, hash: hash}
}

func (w foldWorld) secondSecret() *models.SecretNode {
	w.t.Helper()
	sec, err := w.ls.CreateSecret(context.Background(), &models.SecretNode{
		Name: w.name("pf-secret-2"), ProjectID: w.scope.ProjectID, EnvironmentID: w.scope.EnvironmentID, Status: "active",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(w.t, err)
	return sec
}

func TestFoldedCredential_SameAnswersAsSeparateStatements(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			for _, wantValue := range []bool{true, false} {
				w := newFoldWorld(t, backend)
				ctx := context.Background()
				w.gateReads(ctx) // warm the node cache

				// The separate statements: the credential, then the node read.
				wantCred, wantState, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, w.hash)
				require.NoError(t, err)
				cached, ok := w.ls.secretMetaCache.getNode(w.secret.ID)
				require.True(t, ok)
				pf := storage.ReadPathPrefetchFrom(storage.NewReadPathPrefetch(ctx, w.machine, wantValue))
				wantStamp, wantPerm, wantSched, ok := w.ls.readNodeStampPrefetching(ctx, pf, w.secret.ID, cached.node)
				require.True(t, ok)

				// The folded statement.
				fpf := storage.ReadPathPrefetchFrom(storage.NewReadPathPrefetchFolding(ctx, w.machine, wantValue, w.secret.ID))
				cred, state, folded, ok := w.ls.getMachineCredentialFolded(ctx, w.hash, fpf, w.secret.ID)
				require.True(t, ok)
				require.Equal(t, wantCred, cred, "credential, field for field")
				require.Equal(t, wantState, state, "identity state")
				require.Equal(t, wantStamp, folded.stamp, "node stamp and trigger proof")
				require.Equal(t, cached.generation, folded.entryGeneration)
				require.Equal(t, wantPerm, folded.perm, "roles at the node's scope and the generation")
				require.Equal(t, wantSched, folded.sched, "schedule and versions generation")

				// End to end: one statement answers the credential and all three reads.
				counter := ppCountStatements(t, w.ls.db)
				fctx := storage.NewReadPathPrefetchFolding(ctx, w.machine, wantValue, w.secret.ID)
				var node *models.SecretNode
				var perm *storage.PrincipalPermission
				stmts := counter.during(func() {
					cred, state, err = w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
					require.NoError(t, err)
					node, err = w.ls.GetSecret(fctx, w.secret.ID)
					require.NoError(t, err)
					perm, err = w.ls.ResolveMachinePermissionAt(fctx, w.machine, w.scope, w.perm)
					require.NoError(t, err)
				})
				require.Len(t, stmts, 1, "%v", stmts)
				require.Equal(t, wantCred, cred)
				require.Equal(t, wantState, state)
				require.Equal(t, w.secret.ID, node.ID)
				require.True(t, perm.HasPermission)
			}
		})
	}
}

// A missing secret leaves the credential exactly as the plain statement reads
// it, and parks nothing usable.
func TestFoldedCredential_MissingSecretLeavesCredentialUnchanged(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newFoldWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx)
			wantCred, wantState, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(ctx, w.hash)
			require.NoError(t, err)
			require.NoError(t, w.ls.db.Exec("DELETE FROM secret_nodes WHERE id = ?", w.secret.ID).Error)

			fctx := storage.NewReadPathPrefetchFolding(ctx, w.machine, true, w.secret.ID)
			cred, state, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
			require.NoError(t, err)
			require.Equal(t, wantCred, cred)
			require.Equal(t, wantState, state)
			_, err = w.ls.GetSecret(fctx, w.secret.ID)
			require.Error(t, err, "a deleted secret is not served from the warm entry")
		})
	}
}

// TestFoldedNodeStamp_NotServedToAnotherSecretOrMachine: the parked node answers
// are taken only by GetSecret for the secret they were read for, only for the
// machine whose credential was read, and only once.
func TestFoldedNodeStamp_NotServedToAnotherSecretOrMachine(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newFoldWorld(t, backend)
			ctx := context.Background()
			other := w.secondSecret()
			w.gateReads(ctx)
			_, err := w.ls.GetSecret(ctx, other.ID) // warm the other entry too
			require.NoError(t, err)
			counter := ppCountStatements(t, w.ls.db)

			t.Run("another secret", func(t *testing.T) {
				fctx := storage.NewReadPathPrefetchFolding(ctx, w.machine, true, w.secret.ID)
				_, _, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
				require.NoError(t, err)
				stmts := counter.during(func() {
					n, err := w.ls.GetSecret(fctx, other.ID)
					require.NoError(t, err)
					require.Equal(t, other.ID, n.ID)
				})
				require.Len(t, stmts, 1, "its own stamp read, not the parked one: %v", stmts)
				stmts = counter.during(func() {
					_, err := w.ls.GetSecret(fctx, w.secret.ID)
					require.NoError(t, err)
				})
				require.Len(t, stmts, 1, "taken at most once, the first GetSecret consumed it: %v", stmts)
			})

			t.Run("another machine", func(t *testing.T) {
				fctx := storage.NewReadPathPrefetchFolding(ctx, w.machine2(), true, w.secret.ID)
				cred, _, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
				require.NoError(t, err)
				require.Equal(t, w.machine, cred.MachineIdentityID)
				stmts := counter.during(func() {
					_, err := w.ls.GetSecret(fctx, w.secret.ID)
					require.NoError(t, err)
				})
				require.Len(t, stmts, 1, "nothing parked for a carrier of another machine: %v", stmts)
			})

			t.Run("fold request is one-shot", func(t *testing.T) {
				fctx := storage.NewReadPathPrefetchFolding(ctx, w.machine, true, w.secret.ID)
				_, _, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
				require.NoError(t, err)
				stmts := counter.during(func() {
					_, _, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
					require.NoError(t, err)
				})
				require.Empty(t, stmts, "a second credential read on the request is the plain prepared statement: %v", stmts)
			})
		})
	}
}

// A node that changed after the folded read but before GetSecret is not served:
// the parked stamp is compared with the cached generation.
func TestFoldedNodeStamp_StaleStampIsAMiss(t *testing.T) {
	for _, backend := range principalPermBackends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newFoldWorld(t, backend)
			ctx := context.Background()
			w.gateReads(ctx)
			require.NoError(t, w.ls.db.Exec("UPDATE secret_nodes SET status = 'suspended' WHERE id = ?", w.secret.ID).Error)
			fctx := storage.NewReadPathPrefetchFolding(ctx, w.machine, true, w.secret.ID)
			_, _, err := w.ls.GetMachineIdentityCredentialWithIdentityStateByHash(fctx, w.hash)
			require.NoError(t, err)
			node, err := w.ls.GetSecret(fctx, w.secret.ID)
			require.NoError(t, err)
			require.Equal(t, "suspended", node.Status, "the folded stamp moved: a miss, the live row")
		})
	}
}
