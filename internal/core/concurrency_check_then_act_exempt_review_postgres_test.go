// concurrency_check_then_act_exempt_review_postgres_test.go — C-GUARD2-EXEMPT-REVIEW
// (#2564): the independent second review of docs/check-then-act-lock-exempt.tsv.
// Every test here pins ONE concrete two-replica interleaving that a TSV row's
// "safe" classification did not hold up against, on real Postgres, with each
// replica on its own *gorm.DB connection pool (own LocalStorage, own
// KeyorixCore), exactly like the #1646/#2581 SoD race tests.
//
// How the interleaving is forced (and what that does and does NOT prove):
// rather than looping raceReplicas until a millisecond window happens to line
// up, each test registers a one-shot GORM callback on replica A's OWN
// *gorm.DB (callbacks are per-*gorm.DB, so replica B's connection is never
// hooked) that runs replica B's real, complete core operation — on B's own
// connection, committing on its own — immediately before A's specific write
// statement executes. That is a legal interleaving under Postgres READ
// COMMITTED with no shared lock between the two calls: nothing here reaches
// into either replica's code path, it only chooses WHEN B runs. It proves
// the end state is reachable; it says nothing about how often an unforced
// race hits the window. The precedent for this technique is
// internal/storage/store/concurrency_purge_restore_race_test.go.
//
// Each test is t.Skip'd with its tracking issue: they demonstrate an OPEN
// gap and fail by design until the locking fix lands (locking fixes need
// coordinator review, so this file is test-only). Remove the Skip in the
// fixing PR; the test then goes green.
//
// NEW REVIEW TESTS GO IN THEIR OWN FILE (cta_review_<name>_postgres_test.go, reusing
// newCTAReview below), never appended to the end of this one: appends to a shared
// file were a top merge-conflict source (CHURN-2, internal/core/REGISTRY-ENTRIES.md).
package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/ports"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// ctaReview is one test's two-replica Postgres fixture: a bootstrapped admin
// (global admin, ID adminID), one project with one environment, and two
// independent replicas A and B on their own connections into the same schema.
type ctaReview struct {
	t       *testing.T
	ctx     context.Context
	setupDB *gorm.DB
	setup   *KeyorixCore
	dbA     *gorm.DB
	coreA   *KeyorixCore
	// dbB is replica B's own connection pool, exposed for GUARD-5's
	// interleaving driver (interleave_sync_points_test.go), which needs a
	// sync point on BOTH replicas to force the orderings where A's write
	// lands before B's. beforeA below only ever needed A's.
	dbB       *gorm.DB
	coreB     *KeyorixCore
	enc       ports.EncryptionProvider
	adminID   uint
	projectID uint
	envID     uint
}

func newCTAReview(t *testing.T) *ctaReview {
	t.Helper()
	dsn := pgIsolatedSchemaDSN(t, pgTestDSN(t))
	return newCTAReviewOn(t, func() *gorm.DB { return pgOpen(t, dsn) })
}

// newCTAReviewOn builds the fixture over any backend: open must return a NEW,
// independent connection pool into the same database on every call (one for
// setup, one per replica). newCTAReview is the Postgres instance;
// newCTAReviewSQLite (concurrency_credential_under_suspend_sqlite_test.go) is
// the shared-file SQLite one.
func newCTAReviewOn(t *testing.T, open func() *gorm.DB) *ctaReview {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()

	setupDB := open()
	require.NoError(t, setupDB.AutoMigrate(kxstorage.AllModels()...))

	// One shared key set for every replica: replicas of one install share key
	// material, and the MFA/dynamic-secret tests need B to encrypt what A decrypts.
	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("cta-review-passphrase"))

	newCore := func(db *gorm.DB) *KeyorixCore {
		c := NewKeyorixCore(localstore.NewLocalStorage(db))
		c.SetAuthEncryptor(enc)
		return c
	}
	setup := newCore(setupDB)
	setup.SetBootstrapToken("cta-review-token")
	boot, err := setup.BootstrapSystem(ctx, &BootstrapRequest{
		Username: "admin", Email: "admin@example.com", Password: "BootstrapPass123!",
		DisplayName: "Admin", Token: "cta-review-token",
	})
	require.NoError(t, err)

	proj, err := setup.CreateProject(ctx, "cta-review-project", "")
	require.NoError(t, err)
	env, err := setup.CreateEnvironment(ctx, proj.ID, "cta-review-env")
	require.NoError(t, err)

	dbA := open()
	dbB := open()
	return &ctaReview{
		t: t, ctx: ctx, setupDB: setupDB, setup: setup,
		dbA: dbA, coreA: newCore(dbA), dbB: dbB, coreB: newCore(dbB),
		enc: enc, adminID: boot.User.ID, projectID: proj.ID, envID: env.ID,
	}
}

// user creates an active user with a real password hash and, when
// projectRole != "", a direct grant of that role at the fixture project.
func (f *ctaReview) user(name, projectRole string) *models.User {
	f.t.Helper()
	u, err := f.setup.CreateUser(f.ctx, &CreateUserRequest{
		Username: name, Email: name + "@example.com", DisplayName: name, Password: "UserPass123!xyz-long-enough",
	})
	require.NoError(f.t, err)
	if projectRole != "" {
		role, err := f.setup.Storage().GetRoleByName(f.ctx, projectRole)
		require.NoError(f.t, err)
		require.NoError(f.t, f.setup.Storage().AssignRole(f.ctx, u.ID, role.ID, Scope{ProjectID: f.projectID}))
	}
	return u
}

// secret seeds a live secret owned by ownerID in the fixture project/env.
func (f *ctaReview) secret(name string, ownerID uint) *models.SecretNode {
	f.t.Helper()
	s := &models.SecretNode{Name: name, ProjectID: f.projectID, EnvironmentID: f.envID, IsSecret: true, OwnerID: ownerID}
	require.NoError(f.t, f.setupDB.Create(s).Error)
	return s
}

// beforeA registers a one-shot hook on replica A's own *gorm.DB: immediately
// before A's first `kind` statement ("create" or "update") against `table`
// executes, run `concurrent` (replica B's operation, on B's own connection) to
// completion. Returns a func reporting whether the hook fired, so a test can
// fail loudly if A never reached the write it meant to interleave against
// (a hook that silently never fires would make the test vacuous).
func (f *ctaReview) beforeA(kind, table string, concurrent func()) (fired func() bool) {
	f.t.Helper()
	var once sync.Once
	hit := false
	fn := func(tx *gorm.DB) {
		if tx.Statement.Table != table {
			return
		}
		once.Do(func() {
			hit = true
			concurrent()
		})
	}
	name := "cta-review:before-" + kind + "-" + table
	switch kind {
	case "create":
		require.NoError(f.t, f.dbA.Callback().Create().Before("gorm:create").Register(name, fn))
	case "update":
		require.NoError(f.t, f.dbA.Callback().Update().Before("gorm:update").Register(name, fn))
	default:
		f.t.Fatalf("beforeA: unknown kind %q", kind)
	}
	return func() bool { return hit }
}

// afterA is beforeA's mirror: `concurrent` runs immediately AFTER A's first `kind`
// statement against `table` has executed, while A's enclosing transaction (if any) is
// still open and uncommitted. That is the interleaving a check-BEFORE-write fix would
// miss: B's cascade runs with A's child row already written but invisible to it.
// B must not block on anything A holds at that point, or this deadlocks by design
// (B runs synchronously on A's goroutine) — use it only where A holds no lock B needs.
func (f *ctaReview) afterA(kind, table string, concurrent func()) (fired func() bool) {
	f.t.Helper()
	var once sync.Once
	hit := false
	fn := func(tx *gorm.DB) {
		if tx.Statement.Table != table || tx.Error != nil {
			return
		}
		once.Do(func() {
			hit = true
			concurrent()
		})
	}
	name := "cta-review:after-" + kind + "-" + table
	switch kind {
	case "create":
		require.NoError(f.t, f.dbA.Callback().Create().After("gorm:create").Register(name, fn))
	case "update":
		require.NoError(f.t, f.dbA.Callback().Update().After("gorm:update").Register(name, fn))
	default:
		f.t.Fatalf("afterA: unknown kind %q", kind)
	}
	return func() bool { return hit }
}

func (f *ctaReview) countLive(model any, where string, args ...any) int64 {
	f.t.Helper()
	var n int64
	require.NoError(f.t, f.setupDB.Unscoped().Model(model).Where(where, args...).Count(&n).Error)
	return n
}

// TestCTAReview_ShareSecret_vs_DeleteSecret_CrossReplicaPostgres: a share
// created while the secret is concurrently deleted must not survive as a live
// grant on the deleted secret (#370: "delete means gone for sharing too" —
// a surviving share silently reactivates on RestoreSecret).
func TestCTAReview_ShareSecret_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-owner", "project_admin")
	recipient := f.user("cta-recipient", "project_viewer")
	s := f.secret("cta-share-secret", owner.ID)

	var errB error
	fired := f.beforeA("create", "share_records", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	_, errA := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
	})
	t.Logf("ShareSecret (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's share INSERT")
	require.NoError(t, errB)

	assert.EqualValues(t, 1, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NOT NULL", s.ID), "secret must be deleted")
	assert.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
		"#370 violated: a live share exists on a soft-deleted secret (it reactivates on RestoreSecret)")
}

// TestCTAReview_ShareSecretWithGroup_vs_DeleteSecret_CrossReplicaPostgres: the
// group-recipient sibling of the test above, through the same CreateShareRecord.
func TestCTAReview_ShareSecretWithGroup_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-gowner", "project_admin")
	s := f.secret("cta-gshare-secret", owner.ID)
	g := &models.Group{Name: "cta-group", NameFolded: "cta-group"}
	require.NoError(t, f.setupDB.Create(g).Error)
	viewer, err := f.setup.Storage().GetRoleByName(f.ctx, "project_viewer")
	require.NoError(t, err)
	require.NoError(t, f.setup.Storage().AssignRoleToGroup(f.ctx, g.ID, viewer.ID, Scope{ProjectID: f.projectID}))

	var errB error
	fired := f.beforeA("create", "share_records", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	_, errA := f.coreA.ShareSecretWithGroup(f.ctx, &GroupShareSecretRequest{
		SecretID: s.ID, GroupID: g.ID, Permission: "read", SharedBy: owner.ID,
	})
	t.Logf("ShareSecretWithGroup (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's share INSERT")
	require.NoError(t, errB)

	assert.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
		"#370 violated: a live group share exists on a soft-deleted secret")
}

// TestCTAReview_ShareSecret_DeleteSecretAfterInsert_CrossReplicaPostgres: the
// interleaving the two tests above cannot reach. B's DeleteSecret commits AFTER A's
// share INSERT has run but BEFORE A's transaction commits. B's #370 cascade cannot
// see A's uncommitted row, so a fix that only checked liveness BEFORE the insert
// would still commit a live share on a deleted secret here.
//
// Bug origin (#2646, #2647):
//
//	Introduced-by: #370's DeleteSecret share cascade, which revokes only the shares
//	  visible to its own transaction; CreateShareRecord's read-then-INSERT never
//	  serialized against it.
//	Detected-by: C-GUARD2-EXEMPT-REVIEW #2662
//	Class: cross-replica check-then-act
//	Severity: MEDIUM (a share revoked by deleting the secret reactivates on restore)
//	Guard: this test, the two above, and lockLiveParent's write-then-FOR-SHARE
//	  re-check in LocalStorage.CreateShareRecord (INV-STORE-21).
func TestCTAReview_ShareSecret_DeleteSecretAfterInsert_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-aowner", "project_admin")
	recipient := f.user("cta-arecipient", "project_viewer")
	s := f.secret("cta-ashare-secret", owner.ID)

	var errB error
	fired := f.afterA("create", "share_records", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	_, errA := f.coreA.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
	})
	t.Logf("ShareSecret (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have run B's DeleteSecret after A's share INSERT")
	require.NoError(t, errB)

	assert.EqualValues(t, 1, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NOT NULL", s.ID), "secret must be deleted")
	assert.Error(t, errA, "A must fail closed: its secret was deleted before it committed")
	assert.Zero(t, f.countLive(&models.ShareRecord{}, "secret_id = ? AND deleted_at IS NULL", s.ID),
		"#370 violated: a live share exists on a soft-deleted secret (it reactivates on RestoreSecret)")
}

// TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres: a
// share revoked while a permission update is in flight must stay revoked.
// UpdateShareRecord's Save(struct) matches 0 rows on the soft-deleted share
// and GORM falls back to INSERT ... ON CONFLICT (id) DO UPDATE SET <all
// columns>, deleted_at included — resurrecting the revoked grant.
//
// Bug origin (#2648):
//
//	Introduced-by: LocalStorage.UpdateShareRecord's GORM Save(existing)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (a revoked share is live again)
//	Guard:         this test (pg-gated) + TestUpdateSharePermission_IsColumnScoped
//	Fix:           UpdateShareRecord is a column-scoped UPDATE scoped to
//	               deleted_at IS NULL; matching no row fails closed
func TestCTAReview_UpdateSharePermission_vs_RevokeShare_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	owner := f.user("cta-uowner", "project_admin")
	recipient := f.user("cta-urecipient", "project_viewer")
	s := f.secret("cta-ushare-secret", owner.ID)
	share, err := f.setup.ShareSecret(f.ctx, &ShareSecretRequest{
		SecretID: s.ID, RecipientID: recipient.ID, Permission: "read", SharedBy: owner.ID,
	})
	require.NoError(t, err)

	// MayBlock since SHARE-CAS-1: A now holds the share row lock
	// (LockShareRecordForUpdate) from its in-transaction read, so B's revoke
	// waits for A's commit instead of committing inside A's window; run
	// synchronously in A's hook it would deadlock the test.
	var errB error
	fired, waitB := f.beforeAMayBlock("update", "share_records", func() { errB = f.coreB.RevokeShare(f.ctx, share.ID, owner.ID) })
	_, errA := f.coreA.UpdateSharePermission(f.ctx, &UpdateShareRequest{
		ShareID: share.ID, Permission: "write", UpdatedBy: owner.ID,
	})
	waitB()
	t.Logf("UpdateSharePermission (A) err=%v, RevokeShare (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's RevokeShare before A's share UPDATE")
	require.NoError(t, errB, "the revoke itself reported success")

	assert.Zero(t, f.countLive(&models.ShareRecord{}, "id = ? AND deleted_at IS NULL", share.ID),
		"a share whose revocation reported success is live again")
}

// TestCTAReview_GrantSecretACL_vs_DeleteSecret_CrossReplicaPostgres: an ACL
// grant racing DeleteSecret must not leave an ACL row on the deleted secret
// (DeleteSecret's own CWE-284 cascade exists so ACLs cannot reactivate on
// restore).
func TestCTAReview_GrantSecretACL_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-aclgrantee", "project_viewer")
	s := f.secret("cta-acl-secret", f.adminID)

	var errB error
	fired := f.beforeA("create", "secret_acls", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	t.Logf("GrantSecretACL (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's ACL upsert")
	require.NoError(t, errB)

	assert.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ?", s.ID),
		"CWE-284 cascade violated: an ACL grant exists on a soft-deleted secret (it reactivates on RestoreSecret)")
}

// TestCTAReview_GrantSecretACL_DeleteSecretAfterUpsert_CrossReplicaPostgres: B's
// DeleteSecret commits after A's ACL upsert ran but before A commits, so B's CWE-284
// ACL cascade cannot see A's row. A liveness check before the upsert would pass here.
//
// Bug origin (#2649):
//
//	Introduced-by: DeleteSecret's CWE-284 ACL cascade (local_secrets.go), which deletes
//	  only the grants visible to its own transaction; GrantSecretACL's
//	  requireSecretOrFolderNode-then-upsert never serialized against it.
//	Detected-by: C-GUARD2-EXEMPT-REVIEW #2662
//	Class: cross-replica check-then-act
//	Severity: MEDIUM (an ACL grant severed by deleting the secret reactivates on restore)
//	Guard: this test, the one above, and lockLiveParent's write-then-FOR-SHARE re-check
//	  in LocalStorage.CreateOrUpdateSecretACL (INV-STORE-21).
func TestCTAReview_GrantSecretACL_DeleteSecretAfterUpsert_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	grantee := f.user("cta-aclagrantee", "project_viewer")
	s := f.secret("cta-acla-secret", f.adminID)

	var errB error
	fired := f.afterA("create", "secret_acls", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	errA := f.coreA.GrantSecretACL(f.ctx, f.adminID, s.ID, grantee.ID, []string{"secrets.read"})
	t.Logf("GrantSecretACL (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have run B's DeleteSecret after A's ACL upsert")
	require.NoError(t, errB)

	assert.Error(t, errA, "A must fail closed: its secret was deleted before it committed")
	assert.Zero(t, f.countLive(&models.SecretACL{}, "secret_id = ?", s.ID),
		"CWE-284 cascade violated: an ACL grant exists on a soft-deleted secret (it reactivates on RestoreSecret)")
}

// TestCTAReview_SetSecretAutoRotate_vs_DeleteSecret_CrossReplicaPostgres:
// SetSecretAutoRotate persists its pre-check snapshot with UpdateSecret's
// full-row Save(struct). Against a concurrently deleted secret that Save's
// UPDATE matches 0 rows and GORM's upsert fallback writes deleted_at = NULL —
// undeleting the secret with no RestoreSecret call, no secret.restored audit
// event, and no RestoreSecret parent-liveness check. (The same stale Save
// also overwrites a concurrent admin's rotation-backend binding and a
// concurrent ClearProjectSecretOwnership — see the issue.)
//
// Bug origin (#2650):
//
//	Introduced-by: SetSecretAutoRotate persisting its snapshot via UpdateSecret's Save
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (a deleted secret is live again without RestoreSecret)
//	Guard:         this test (pg-gated) + TestSetSecretAutoRotate_IsColumnScoped
//	Fix:           UpdateSecretRotationConfig — rotation columns only, WHERE the
//	               row is live, in the same project, and still bound to the
//	               pre-read backend; matching no row fails closed
func TestCTAReview_SetSecretAutoRotate_vs_DeleteSecret_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s := f.secret("cta-rotate-secret", f.adminID)

	var errB error
	fired := f.beforeA("update", "secret_nodes", func() { errB = f.coreB.DeleteSecret(f.ctx, s.ID) })
	errA := f.coreA.SetSecretAutoRotate(f.ctx, s.ID, AutoRotateSpec{Enabled: true, Length: 32}, f.adminID)
	t.Logf("SetSecretAutoRotate (A) err=%v, DeleteSecret (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteSecret before A's secret UPDATE")
	require.NoError(t, errB, "the delete itself reported success")

	assert.Zero(t, f.countLive(&models.SecretNode{}, "id = ? AND deleted_at IS NULL", s.ID),
		"a secret whose deletion reported success is live again, without RestoreSecret")
}

// TestCTAReview_CreateDynamicSecretConfig_vs_DeleteProject_CrossReplicaPostgres:
// the original race (#2651): CreateDynamicSecretConfig inserted the row, then wrote
// the encrypted DSN in a second, separately committed write. DeleteProject landing
// between the two disabled the (visible) config (#369); a stale full-row Save then
// wrote disabled=false back. RestoreProject deliberately does not re-enable configs
// (#369), so that left a config able to mint credentials once the project was restored.
//
// Why the interleave point moved (#3108/#3110): the insert and the DSN write now run in
// ONE transaction, and its project FOR SHARE re-check (lockLiveParent) holds until
// commit. The old hook (B's DeleteProject run synchronously, on A's goroutine, just
// before A's DSN UPDATE) now sits INSIDE that transaction, where A holds the project
// row lock B's cascade needs (lockProjectRowForCascade): B waits for A, A waits for the
// hook that is running B, and the test hangs. That is a harness deadlock of its own
// making, not a product bug: replicas A and B really are on different goroutines. The
// interleave that is still meaningful is "B lands while A is mid-transaction, after its
// insert and project lock, before its commit". So the hook now starts B on its OWN
// goroutine, waits (bounded, via pg_blocking_pids on A's backend) until B is observed
// blocked behind A, and lets A commit. The safe serialization is: B's cascade runs after
// A's commit, sees the committed config and disables it. The assertions check exactly
// that: both operations succeed and the committed config is disabled. If B did not
// serialize behind A it would not see A's uncommitted row, and the config would commit
// enabled under a deleted project (the #369 violation asserted below).
// The pre-transaction interleave is covered by
// TestCTAReview_CreateDynamicSecretConfig_DeleteProjectBeforeTx_CrossReplicaPostgres.
func TestCTAReview_CreateDynamicSecretConfig_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	f.coreA.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	f.coreB.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

	const bound = 60 * time.Second
	bDone := make(chan error, 1)
	var once sync.Once
	var fired, bBlockedBehindA bool
	require.NoError(t, f.dbA.Callback().Update().Before("gorm:update").Register("cta-review:concurrent-delete-in-tx", func(tx *gorm.DB) {
		if tx.Statement.Table != "dynamic_secret_configs" {
			return
		}
		once.Do(func() {
			fired = true
			var aPID int
			require.NoError(t, tx.Statement.ConnPool.QueryRowContext(f.ctx, "SELECT pg_backend_pid()").Scan(&aPID))
			go func() { bDone <- f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) }()
			// Bounded wait until B's backend is blocked behind A's transaction.
			deadline := time.Now().Add(bound)
			for time.Now().Before(deadline) {
				var n int64
				require.NoError(t, f.setupDB.Raw("SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))", aPID).Scan(&n).Error)
				if n > 0 {
					bBlockedBehindA = true
					return
				}
				select {
				case err := <-bDone: // B finished without ever waiting for A: it did not serialize.
					bDone <- err
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		})
	}))

	cfg, errA := f.coreA.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-dyn", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	require.True(t, fired, "the hook must have started B's DeleteProject inside A's transaction")
	var errB error
	select {
	case errB = <-bDone:
	case <-time.After(bound):
		t.Fatalf("B's DeleteProject did not finish within %s after A's transaction ended", bound)
	}
	t.Logf("CreateDynamicSecretConfig (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, bBlockedBehindA, "B's DeleteProject must block behind A's open transaction (the project row lock), else this run did not exercise the serialization")
	require.NoError(t, errA)
	require.NoError(t, errB)

	var got models.DynamicSecretConfig
	require.NoError(t, f.setupDB.First(&got, cfg.ID).Error)
	assert.True(t, got.Disabled, "#369 violated: a config in a deleted project is enabled (it mints again the moment the project is restored)")
}

// TestCTAReview_CreateDynamicSecretConfig_DeleteProjectAfterInsert_CrossReplicaPostgres:
// B's DeleteProject commits after A's config INSERT ran but before A's insert
// transaction commits. B's #369 disable cannot see A's uncommitted row, so without the
// insert's own project re-check the config would commit enabled under the deleted
// project, the same end state as the stale Save above, reached through the insert.
//
// Bug origin (#2651):
//
//	Introduced-by: #94's insert-then-encrypt-then-Save split in
//	  CreateDynamicSecretConfig: the second write was a full-row Save, and the insert
//	  never re-checked its project against #369's cascade.
//	Detected-by: C-GUARD2-EXEMPT-REVIEW #2662
//	Class: cross-replica check-then-act
//	Severity: MEDIUM (an enabled config in a deleted project mints again on restore,
//	  with no explicit re-enable)
//	Guard: this test, the one above, SetDynamicSecretConfigAdminDSN's targeted write,
//	  and lockLiveParent's write-then-FOR-SHARE project re-check in
//	  LocalStorage.CreateDynamicSecretConfig (INV-STORE-21).
func TestCTAReview_CreateDynamicSecretConfig_DeleteProjectAfterInsert_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	f.coreA.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	f.coreB.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })

	var errB error
	fired := f.afterA("create", "dynamic_secret_configs", func() { errB = f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) })
	_, errA := f.coreA.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-dyn-after", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	t.Logf("CreateDynamicSecretConfig (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have run B's DeleteProject after A's config INSERT")
	require.NoError(t, errB)

	assert.Error(t, errA, "A must fail closed: its project was deleted before its insert committed")
	assert.Zero(t, f.countLive(&models.DynamicSecretConfig{}, "project_id = ? AND disabled = ?", f.projectID, false),
		"#369 violated: an enabled dynamic-secret config exists in a deleted project")
}

// TestCTAReview_IssueLease_vs_DeleteProject_CrossReplicaPostgres: a lease
// issued while the project is concurrently deleted must not survive as an
// active, never-revoked credential. DeleteProject's lease revocation lists
// leases BEFORE A's lease row exists, and nothing re-checks afterwards.
func TestCTAReview_IssueLease_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	}
	cfg, err := f.setup.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-lease", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("create", "dynamic_secret_leases", func() { errB = f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) })
	lease, errA := f.coreA.IssueLease(f.ctx, cfg.ID, 0, f.adminID)
	t.Logf("IssueLease (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteProject before A's lease INSERT")
	require.NoError(t, errB)

	active := f.countLive(&models.DynamicSecretLease{}, "config_id = ? AND status = ?", cfg.ID, "active")
	if errA == nil {
		t.Logf("issued lease %s; backend revocations: %v", lease.LeaseID, fake.Revoked)
	}
	assert.Zero(t, active,
		"#369 violated: an active, never-revoked dynamic-secret lease exists under a deleted project and a disabled config")
}

// TestCTAReview_IssueLease_DeleteProjectAfterInsert_CrossReplicaPostgres: B's
// DeleteProject commits after A's lease INSERT ran but before A commits. B's
// post-commit lease revocation lists leases before A's row is visible, so a check
// before the insert would pass and leave the credential live and never revoked.
//
// Bug origin (#2652):
//
//	Introduced-by: #369's DeleteProject cascade, which disables configs in its
//	  transaction and revokes only the leases it can list after committing;
//	  IssueLease's liveness check, mint, then insert never serialized against it.
//	Detected-by: C-GUARD2-EXEMPT-REVIEW #2662
//	Class: cross-replica check-then-act
//	Severity: HIGH (a live database credential under a deleted project, never revoked
//	  until its TTL)
//	Guard: this test, the one above, and lockLiveParent's write-then-FOR-SHARE re-check
//	  of the config in LocalStorage.CreateDynamicSecretLease (INV-STORE-21).
func TestCTAReview_IssueLease_DeleteProjectAfterInsert_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	fake := &dynamictest.FakeEngine{NativeExpiry: true}
	for _, c := range []*KeyorixCore{f.setup, f.coreA, f.coreB} {
		c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	}
	cfg, err := f.setup.CreateDynamicSecretConfig(f.ctx, &CreateDynamicSecretConfigRequest{
		Name: "cta-lease-after", ProjectID: f.projectID, EnvironmentID: f.envID, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "admin", ActorID: f.adminID,
	})
	require.NoError(t, err)

	var errB error
	fired := f.afterA("create", "dynamic_secret_leases", func() { errB = f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) })
	_, errA := f.coreA.IssueLease(f.ctx, cfg.ID, 0, f.adminID)
	t.Logf("IssueLease (A) err=%v, DeleteProject (B) err=%v, backend revocations: %v", errA, errB, fake.Revoked)
	require.True(t, fired(), "the hook must have run B's DeleteProject after A's lease INSERT")
	require.NoError(t, errB)

	assert.Error(t, errA, "A must fail closed: its config was disabled before it committed")
	assert.Zero(t, f.countLive(&models.DynamicSecretLease{}, "config_id = ? AND status = ?", cfg.ID, "active"),
		"#369 violated: an active, never-revoked dynamic-secret lease exists under a deleted project and a disabled config")
	assert.Len(t, fake.Revoked, 1, "the credential minted for the refused lease must have been revoked on the target")
}

// TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres: an admin's
// display-name edit in flight must not undo another admin's concurrent
// suspension. UpdateUser's default branch writes the full pre-read row
// (Select("*")) gated only on is_active, and SuspendUser changes
// account_state, not is_active — so the stale account_state='active' wins.
//
// Bug origin (#2653):
//
//	Introduced-by: UpdateUserIfActiveStateMatches's Select("*") full-row write
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (a reported-successful suspension is reverted)
//	Guard:         this test (pg-gated) + TestUserProfileWrites_AreColumnScoped
//	Fix:           the write is column-scoped to the profile columns UpdateUser owns
func TestCTAReview_UpdateUser_vs_SuspendUser_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	target := f.user("cta-suspendee", "project_viewer")

	var errB error
	fired := f.beforeA("update", "users", func() { errB = f.coreB.SuspendUser(f.ctx, f.adminID, target.ID) })
	_, errA := f.coreA.UpdateUser(f.ctx, &UpdateUserRequest{ID: target.ID, ActorID: f.adminID, DisplayName: "renamed"})
	t.Logf("UpdateUser (A) err=%v, SuspendUser (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's SuspendUser before A's user UPDATE")
	require.NoError(t, errB, "the suspension itself reported success")

	var got models.User
	require.NoError(t, f.setupDB.First(&got, target.ID).Error)
	assert.Equal(t, AccountSuspended, got.AccountState, "a suspension that reported success was silently reverted")
}

// TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres: the
// self-service sibling of the test above, reachable with only a session. A
// display-name-only profile update (no re-auth) in flight while the account
// holder changes their password writes the OLD password hash back.
//
// Bug origin (#2654):
//
//	Introduced-by: UpdateUserIfActiveStateMatches's Select("*") full-row write
//	               (UpdateOwnProfile reaches it through UpdateUser's default branch)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (only a session needed to revert a password change,
//	               suspension or MFA enable)
//	Guard:         this test (pg-gated) + TestUserProfileWrites_AreColumnScoped
//	Fix:           same as #2653 — the write is column-scoped
func TestCTAReview_UpdateOwnProfile_vs_ChangePassword_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	victim := f.user("cta-victim", "project_viewer")
	var before models.User
	require.NoError(t, f.setupDB.First(&before, victim.ID).Error)

	var errB error
	fired := f.beforeA("update", "users", func() {
		errB = f.coreB.ChangePassword(f.ctx, victim.ID, "UserPass123!xyz-long-enough", "NewUserPass456!abc-long-enough", "")
	})
	_, errA := f.coreA.UpdateOwnProfile(f.ctx, victim.ID, "stale-session-rename", "", "")
	t.Logf("UpdateOwnProfile (A) err=%v, ChangePassword (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's ChangePassword before A's user UPDATE")
	require.NoError(t, errB, "the password change itself reported success")

	var got models.User
	require.NoError(t, f.setupDB.First(&got, victim.ID).Error)
	assert.NotEqual(t, before.PasswordHash, got.PasswordHash, "the OLD password hash is live again after a successful password change")
}

// TestCTAReview_ActivateMFA_vs_BeginMFAEnrollment_CrossReplicaPostgres: the
// TOTP secret ActivateMFA activates must be the one the submitted code was
// validated against. ActivateMFASecret was UPDATE ... WHERE user_id = ?, with
// nothing pinning the secret; a re-enrolment (e.g. from a stolen session)
// landing between validation and activation got activated instead. Fixed by
// pinning the conditional write to the validated ciphertext: under the forced
// interleaving activation must now fail closed, leaving MFA off and the
// replacement secret unactivated.
//
// Bug origin
//
//	Introduced-by: #G08 (activation moved into one transaction, but the
//	               activating UPDATE never re-asserted which secret it activates)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (MFA bound to a secret an attacker controls)
//	Guard:         this test + TestActivateMFA_SecretSwappedAfterValidation_FailsClosed
func TestCTAReview_ActivateMFA_vs_BeginMFAEnrollment_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	victim := f.user("cta-mfa", "")
	_, s1, err := f.setup.BeginMFAEnrollment(f.ctx, victim.ID)
	require.NoError(t, err)
	code, err := totp.GenerateCode(s1, time.Now())
	require.NoError(t, err)

	var errB error
	fired := f.beforeA("update", "mfa_secrets", func() { _, _, errB = f.coreB.BeginMFAEnrollment(f.ctx, victim.ID) })
	_, errA := f.coreA.ActivateMFA(f.ctx, victim.ID, code, "UserPass123!xyz-long-enough", "")
	t.Logf("ActivateMFA (A) err=%v, BeginMFAEnrollment (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's BeginMFAEnrollment before A's activation UPDATE")
	require.NoError(t, errB)
	assertActivationNeverBindsUnvalidatedSecret(t, f.setup, victim.ID, s1, errA)
}

// assertActivationNeverBindsUnvalidatedSecret: either ActivateMFA failed closed
// (ErrMFAEnrollmentChanged, MFA off, stored secret not activated), or it
// succeeded and the activated secret is the one the code was validated
// against. With the swap forced before activation, only the first is legal.
func assertActivationNeverBindsUnvalidatedSecret(t *testing.T, c *KeyorixCore, userID uint, validated string, activateErr error) {
	t.Helper()
	ctx := context.Background()
	row, err := c.Storage().GetMFASecret(ctx, userID)
	require.NoError(t, err)
	// Decrypted directly, not via loadTOTPSecret: that refuses a pending
	// secret (#2692), and the fail-closed outcome leaves exactly one.
	active, err := c.decryptAuthSecret(row.SecretEnc, row.SecretMeta, ports.MFASecretAAD(userID))
	require.NoError(t, err)
	user, err := c.Storage().GetUser(ctx, userID)
	require.NoError(t, err)
	t.Logf("activate err=%v, secret swapped=%v, activated=%v, MFAEnabled=%v", activateErr, active != validated, row.Activated, user.MFAEnabled)
	assert.False(t, row.Activated && active != validated,
		"MFA was activated with a TOTP secret the account holder never validated a code against")
	require.ErrorIs(t, activateErr, ErrMFAEnrollmentChanged, "the secret was swapped before activation: it must fail closed")
	assert.False(t, user.MFAEnabled, "a failed activation must roll back MFAEnabled")
	assert.False(t, row.Activated)
}

// TestCTAReview_RestoreEnvironment_vs_DeleteProject_CrossReplicaPostgres:
// LocalStorage.RestoreEnvironment checks project liveness in one autocommit
// SELECT and un-deletes in a separate UPDATE; a DeleteProject committing in
// between (its cascade skips the already-deleted environment) leaves a live
// environment under a deleted project — the exact state RestoreEnvironment's
// own doc comment says it refuses to create.
func TestCTAReview_RestoreEnvironment_vs_DeleteProject_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	require.NoError(t, f.setup.DeleteEnvironment(f.ctx, f.envID))

	var errB error
	fired := f.beforeA("update", "environments", func() { errB = f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) })
	errA := f.coreA.RestoreEnvironment(f.ctx, f.adminID, f.projectID, f.envID)
	t.Logf("RestoreEnvironment (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have interleaved B's DeleteProject before A's environment UPDATE")
	require.NoError(t, errB)

	assert.EqualValues(t, 1, f.countLive(&models.Project{}, "id = ? AND deleted_at IS NOT NULL", f.projectID), "project must be deleted")
	assert.Zero(t, f.countLive(&models.Environment{}, "project_id = ? AND deleted_at IS NULL", f.projectID),
		"a live environment exists under a soft-deleted project")
}

// TestCTAReview_RestoreEnvironment_DeleteProjectAfterUpdate_CrossReplicaPostgres: B's
// DeleteProject commits after A's environment UPDATE ran but before A commits. B's
// environment sweep cannot see A's uncommitted un-delete, so a liveness check before
// the UPDATE (or a FOR SHARE that DeleteProject only meets at its final project
// UPDATE) would still leave E live under the deleted P.
//
// Bug origin (#2656):
//
//	Introduced-by: LocalStorage.RestoreEnvironment's parent-liveness guard, a separate
//	  autocommit SELECT before an unconditional UPDATE; deleteProjectCascade swept
//	  environments before it touched (locked) the project row.
//	Detected-by: C-GUARD2-EXEMPT-REVIEW #2662
//	Class: cross-replica check-then-act
//	Severity: LOW (millisecond window, timed by the deleting admin)
//	Guard: this test, the one above, deleteProjectCascade's up-front project row lock,
//	  and lockLiveParent's write-then-FOR-SHARE re-check in RestoreEnvironment
//	  (INV-STORE-21).
//
// TestCTAReview_RestoreEnvironment_InsideDeleteProjectCascade_CrossReplicaPostgres:
// A's whole RestoreEnvironment runs between B's environment sweep and B's final
// project UPDATE, the window the two tests above cannot reach because B always runs
// to completion inside A's hook. Here a hook on B's own connection starts A in a
// goroutine and waits for it (bounded). Without deleteProjectCascade's up-front
// project row lock, A's FOR SHARE re-check passes (the project is not yet updated),
// A commits, and B then deletes the project over the live environment. With the lock,
// A blocks on it, the wait times out, B commits, and A's re-check then sees the
// project deleted and rolls back.
func TestCTAReview_RestoreEnvironment_InsideDeleteProjectCascade_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	require.NoError(t, f.setup.DeleteEnvironment(f.ctx, f.envID))

	var errA error
	doneA := make(chan struct{})
	var once sync.Once
	hit := false
	require.NoError(t, f.dbB.Callback().Update().Before("gorm:update").Register("cta-review:b-before-update-projects", func(tx *gorm.DB) {
		if tx.Statement.Table != "projects" {
			return
		}
		once.Do(func() {
			hit = true
			go func() {
				errA = f.coreA.RestoreEnvironment(f.ctx, f.adminID, f.projectID, f.envID)
				close(doneA)
			}()
			select {
			case <-doneA: // A finished inside the window: nothing held it back
			case <-time.After(2 * time.Second): // A is blocked (on B's project row lock); let B commit
			}
		})
	}))

	errB := f.coreB.DeleteProject(f.ctx, 0, f.projectID, true)
	require.True(t, hit, "the hook must have fired before B's project UPDATE")
	require.NoError(t, errB)
	select {
	case <-doneA:
	case <-time.After(30 * time.Second):
		t.Fatal("A's RestoreEnvironment never returned after B committed")
	}
	t.Logf("RestoreEnvironment (A) err=%v, DeleteProject (B) err=%v", errA, errB)

	assert.EqualValues(t, 1, f.countLive(&models.Project{}, "id = ? AND deleted_at IS NOT NULL", f.projectID), "project must be deleted")
	assert.Zero(t, f.countLive(&models.Environment{}, "project_id = ? AND deleted_at IS NULL", f.projectID),
		"a live environment exists under a soft-deleted project")
}

func TestCTAReview_RestoreEnvironment_DeleteProjectAfterUpdate_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	require.NoError(t, f.setup.DeleteEnvironment(f.ctx, f.envID))

	var errB error
	fired := f.afterA("update", "environments", func() { errB = f.coreB.DeleteProject(f.ctx, 0, f.projectID, true) })
	errA := f.coreA.RestoreEnvironment(f.ctx, f.adminID, f.projectID, f.envID)
	t.Logf("RestoreEnvironment (A) err=%v, DeleteProject (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have run B's DeleteProject after A's environment UPDATE")
	require.NoError(t, errB)

	assert.EqualValues(t, 1, f.countLive(&models.Project{}, "id = ? AND deleted_at IS NOT NULL", f.projectID), "project must be deleted")
	assert.Error(t, errA, "A must fail closed: its project was deleted before it committed")
	assert.Zero(t, f.countLive(&models.Environment{}, "project_id = ? AND deleted_at IS NULL", f.projectID),
		"a live environment exists under a soft-deleted project")
}

// TestCTAReview_TransitionMembership_ActivateVsRevoke_CrossReplicaPostgres: a
// membership revoked while its activation is in flight must not end up
// `revoked` with the role grant live. Activation commits the provisioned→
// active CAS, THEN grants; a revoke landing between finds no grant
// (ErrNotProjectMember, deliberately ignored) and reports success; the
// activation's grant then lands.
//
// Bug origin
//
//	Introduced-by: #G42 (the state CAS made the transition conditional, but not
//	               together with its grant side effect)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (a revoked member keeps live project access)
//	Guard:         this test; fixed by membershipLockKey (#2657)
func TestCTAReview_TransitionMembership_ActivateVsRevoke_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	u := f.user("cta-member", "")
	m, err := f.setup.Storage().CreateProjectMembership(f.ctx, &models.ProjectMembership{
		ProjectID: f.projectID, UserID: u.ID, Role: "project_viewer", State: MembershipProvisioned,
	})
	require.NoError(t, err)

	var errB error
	fired, waitB := f.beforeAMayBlock("create", "user_roles", func() {
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	_, errA := f.coreA.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipActive, f.adminID, false)
	waitB()
	t.Logf("activate (A) err=%v, revoke (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have started B's revoke before A's role-grant INSERT")
	require.NoError(t, errA)
	require.NoError(t, errB, "the revoke itself reported success")

	got, err := f.setup.Storage().GetProjectMembership(f.ctx, m.ID)
	require.NoError(t, err)
	member, err := f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	t.Logf("final membership state=%s, holds project grant=%v", got.State, member)
	assert.False(t, got.State == MembershipRevoked && member,
		"membership is `revoked` (terminal) yet the user still holds the project role grant")
}

// TestCTAReview_InviteMemberOpenMode_vs_Revoke_CrossReplicaPostgres: the
// invite-path sibling of the test above. In `open` validation mode
// inviteMemberWithMode commits the membership straight as `active`, THEN
// grants the role; a revoke landing between finds no grant and reports
// success, and the invite's grant then lands.
//
// Bug origin
//
//	Introduced-by: open validation mode (inviteMemberWithMode commits `active`
//	               before granting, with no lock shared with revoke)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      high (a revoked member keeps live project access)
//	Guard:         this test; fixed by membershipLockKey (#2659)
func TestCTAReview_InviteMemberOpenMode_vs_Revoke_CrossReplicaPostgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	f.coreA.SetMembershipValidationMode(ValidationModeOpen)
	u := f.user("cta-invitee", "")

	var errB error
	fired, waitB := f.beforeAMayBlock("create", "user_roles", func() {
		m, err := f.coreB.Storage().GetActiveProjectMembership(f.ctx, f.projectID, u.ID)
		if err != nil {
			errB = err
			return
		}
		_, errB = f.coreB.TransitionMembership(f.ctx, f.projectID, m.ID, MembershipRevoked, f.adminID, false)
	})
	created, errA := f.coreA.InviteMember(f.ctx, f.projectID, u.ID, "project_viewer", f.adminID, 0, false)
	waitB()
	t.Logf("invite (A) err=%v, revoke (B) err=%v", errA, errB)
	require.True(t, fired(), "the hook must have started B's revoke before A's role-grant INSERT")
	require.NoError(t, errA)
	require.NoError(t, errB, "the revoke itself reported success")

	got, err := f.setup.Storage().GetProjectMembership(f.ctx, created.ID)
	require.NoError(t, err)
	member, err := f.setup.Storage().IsProjectMember(f.ctx, u.ID, f.projectID)
	require.NoError(t, err)
	t.Logf("final membership state=%s, holds project grant=%v", got.State, member)
	assert.False(t, got.State == MembershipRevoked && member,
		"membership is `revoked` (terminal) yet the user still holds the project role grant")
}

// TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres: INV-CORE-31
// says the dependency graph stays acyclic "including under concurrent adds".
// Its existing guard (TestAddSecretDependency_ConcurrentRaceCannotPersistACycle)
// races two goroutines through ONE KeyorixCore on SQLite, so it is serialized
// by that core's own secretDependencyMu and never exercises two replicas.
// Cross-replica, CreateSecretDependencyExclusive's SELECT ... FOR UPDATE locks
// only edges that already exist: B's locking read blocks on A's locks, and
// under READ COMMITTED it then returns its statement-start snapshot — WITHOUT
// A's just-committed edge — so B's cycle check passes and both edges commit.
//
// Unlike the tests above, B cannot run to completion inside A's hook (it
// blocks on A's own row locks), so the hook starts B in a goroutine, waits
// until Postgres reports a backend waiting on a lock, and only then lets A's
// INSERT and COMMIT proceed. With the #2660 fix B blocks on the per-project
// named lock A holds instead, and runs its cycle check after A commits.
//
// Bug origin
//
//	Introduced-by: #260 (CreateSecretDependencyExclusive relied on FOR UPDATE of
//	               existing edges, which does not block phantom inserts)
//	Detected-by:   C-GUARD2-EXEMPT-REVIEW #2662
//	Class:         cross-replica check-then-act
//	Severity:      medium (INV-CORE-31 integrity: a persisted dependency cycle)
//	Guard:         this test; fixed by secretDependencyGraphLockKey
func TestCTAReview_AddSecretDependency_CrossReplicaCycle_Postgres(t *testing.T) {
	t.Parallel()
	f := newCTAReview(t)
	s1 := f.secret("cta-dep-1", f.adminID)
	s2 := f.secret("cta-dep-2", f.adminID)
	s3 := f.secret("cta-dep-3", f.adminID)
	// One pre-existing edge, so the project has a row for FOR UPDATE to lock
	// (with zero edges there is nothing to lock at all).
	_, err := f.setup.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s3.ID, s1.ID, "", 0)
	require.NoError(t, err)

	var errB error
	done := make(chan struct{})
	fired := f.beforeA("create", "secret_dependencies", func() {
		go func() {
			defer close(done)
			_, errB = f.coreB.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s2.ID, s1.ID, "", 0)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-done:
				return
			default:
			}
			var waiting int64
			require.NoError(t, f.setupDB.Raw(
				"SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'").
				Scan(&waiting).Error)
			if waiting > 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	_, errA := f.coreA.AddSecretDependency(f.ctx, ActorTypeUser, f.adminID, s1.ID, s2.ID, "", 0)
	require.True(t, fired(), "the hook must have started B's add before A's edge INSERT")
	<-done
	t.Logf("add s1->s2 (A) err=%v, add s2->s1 (B) err=%v", errA, errB)

	both := f.countLive(&models.SecretDependency{},
		"(dependent_secret_id = ? AND depends_on_secret_id = ?) OR (dependent_secret_id = ? AND depends_on_secret_id = ?)",
		s1.ID, s2.ID, s2.ID, s1.ID)
	assert.Less(t, both, int64(2), "INV-CORE-31 violated: both s1->s2 and s2->s1 committed — a dependency cycle")
	assert.NoError(t, errA, "A held the graph lock first, so its edge commits")
	assert.ErrorContains(t, errB, "cycle", "B's cycle check must run after A commits and refuse s2->s1")
}
