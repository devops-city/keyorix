// dynamic_config_reenable_parent_liveness_test.go — GUARD-5 item 3's only NEW
// finding: SetDynamicSecretConfigEnabled re-enables a dynamic-secret config
// inside a SOFT-DELETED project, with no concurrency involved at all.
//
// # HOW IT WAS FOUND, AND WHY THAT MATTERS
//
// The ordering sweep (cross_replica_ordering_sweep_test.go) runs each
// conflicting pair through all six legal interleavings — INCLUDING the two
// SERIAL ones, where the two operations never overlap. The serial orderings
// are in the sweep as a control group: an invariant that breaks when nothing
// is concurrent is not a race, and reporting it as one sends the fix to the
// wrong layer (a lock, instead of the missing check).
//
// That control group earned its place on the sweep's first complete run.
// DeleteProject followed by SetDynamicSecretConfigEnabled(true) — strictly
// sequential, A to completion, then B to completion — leaves an enabled
// dynamic-secret config under a soft-deleted project. Every other finding in
// that run was a known open issue reproducing under more orderings than its
// report described; this one is a different bug in a neighbouring function,
// and a two-replica fuzzer could have run for a year without separating it
// from #2651, whose race it looks exactly like in the invariant output.
//
// NOT #2651. #2651 is CreateDynamicSecretConfig's second Save racing
// DeleteProject: a stale full-row write putting disabled=false back. This is
// the ENABLE path, used deliberately, serially, by one API call. PR #2675
// (which fixes #2651) leaves SetDynamicSecretConfigEnabled byte-for-byte
// unchanged — checked against its branch, not assumed.
//
// REACHABILITY, traced rather than inferred (CLAUDE.md: "a Go call graph is
// not a deployment path"):
//
//	PATCH /api/v1/dynamic-secrets/configs/{id}/enabled
//	  -> DynamicSecretHandler.SetConfigEnabled (server/http/handlers/dynamic_secrets.go)
//	  -> h.loadConfig  — resolves the config by id; does NOT check project liveness
//	  -> core.SetDynamicSecretConfigEnabled — no project-liveness check either
//
// The handler's own doc comment says this endpoint exists precisely so "an
// admin re-enables one afterward (project restore deliberately does not do so
// on its own)" — i.e. re-enabling after a delete is the intended use. What is
// missing is the ordering constraint: restore the project FIRST. Nothing
// enforces it, and the scoped-permission middleware does not object, because
// the actor's project-scoped role grant survives the project's soft-delete.
//
// SEVERITY, measured rather than assumed. The first draft of this file claimed
// the re-enabled config mints credentials immediately. Running it showed that
// is NOT true: IssueLease has its own project-liveness check
// (internal/storage/store/local_secrets.go resolves the project with
// `deleted_at IS NULL`) and refuses. So the live impact is narrower than it
// first looked, and saying so is the point — an overclaimed severity is how a
// real finding gets dismissed along with its exaggeration.
//
// What the bug actually is: #369's rule is that a project's configs stay
// disabled across a delete AND across a later restore, so that re-enabling
// one is always a fresh, deliberate, audited decision taken while the project
// is live. This path lets the enable decision be taken while the project is
// deleted, where it is invisible in every project-scoped view, and it then
// takes effect silently the instant someone restores the project — with no
// re-authorization at that moment and nothing in the restore's own audit
// trail about a credential-minting config coming back. That is a latent
// privilege-restoration bug (the same shape as #370's "a share silently
// reactivates on restore"), not immediate credential minting.
//
// The end-to-end mint assertion at the bottom is kept anyway, as a
// belt-and-braces guard on that second layer: if IssueLease's project check is
// ever refactored away, this test starts failing on the mint too rather than
// quietly becoming the only thing standing between a deleted project and a
// real credential.
//
// Deliberately SQLite and not Postgres, unlike the rest of this campaign's
// tests: there is no race here, so there is nothing for a second connection
// pool to demonstrate, and a serial bug's regression test belongs in the
// default CI path rather than behind a DSN gate. Modelled on
// catalog_delete_project_test.go's own #369 fixture.
package core_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/dynamic"
	"github.com/keyorixhq/keyorix/internal/dynamic/dynamictest"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// TestSetDynamicSecretConfigEnabled_RefusesUnderDeletedProject is #2806's
// regression test, green since the fix in SetDynamicSecretConfigEnabled.
func TestSetDynamicSecretConfigEnabled_RefusesUnderDeletedProject(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{},
		&models.ShareRecord{}, &models.AccessRequest{}, &models.SecretACL{}, &models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
		&models.AuditEvent{}, &models.Role{}, &models.UserRole{}, &models.Group{},
		&models.UserGroup{}, &models.GroupRole{}))

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))
	fake := &dynamictest.FakeEngine{NativeExpiry: true}

	c := core.NewKeyorixCore(store.NewLocalStorage(db))
	c.SetAuthEncryptor(enc)
	c.SetDynamicEngineFactory(func(string) (dynamic.CredentialEngine, error) { return fake, nil })
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "env"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	const actorID = uint(42)
	require.NoError(t, db.Create(&models.UserRole{UserID: actorID, RoleID: 1}).Error)

	cfg, err := c.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name: "app-db", ProjectID: 1, EnvironmentID: 1, BackendType: "postgres",
		AdminDSN:          "postgres://admin:s3cr3t@db.internal:5432/app",
		CreationTemplate:  "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};",
		DefaultTTLSeconds: 3600, CreatedBy: "alice", ActorID: actorID,
	})
	require.NoError(t, err)

	// #369: the delete disables the config so it can no longer mint.
	require.NoError(t, c.DeleteProject(ctx, 0, 1, false))
	disabled, err := c.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	require.True(t, disabled.Disabled, "precondition: the delete must have disabled the config")
	_, err = c.IssueLease(ctx, cfg.ID, 0, 7)
	require.Error(t, err, "precondition: a disabled config must refuse to mint")

	// The finding: one call, no concurrency, and #369's guarantee is gone.
	// The project is NOT restored first, and nothing requires it to be.
	_, enableErr := c.SetDynamicSecretConfigEnabled(ctx, actorID, cfg.ID, true)

	after, err := c.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	t.Logf("SetDynamicSecretConfigEnabled(true) err=%v; config disabled=%v", enableErr, after.Disabled)

	// Assert the EFFECT, not the return value: on the buggy code the call
	// reports success, so a return-value assertion alone would be satisfied by
	// a fix that errors but still writes, and by no fix at all if the error
	// were ever downgraded to a warning.
	assert.Error(t, enableErr,
		"#369 violated: enabling a dynamic-secret config under a soft-deleted project must fail closed")
	assert.True(t, after.Disabled,
		"#369 violated: the config is enabled again while its project is still soft-deleted")

	// Belt and braces, NOT the primary claim: on main today IssueLease's own
	// project-liveness check refuses this, which is why the finding is a
	// latent restore-time bug rather than immediate minting. Asserted so that
	// removing that second layer cannot go unnoticed.
	lease, mintErr := c.IssueLease(ctx, cfg.ID, 0, 7)
	if mintErr == nil {
		t.Errorf("SECOND LAYER GONE: minted lease %s against a config in a soft-deleted project. "+
			"IssueLease used to refuse this independently; with that check gone, the re-enable above "+
			"mints real credentials under a deleted project.", lease.LeaseID)
	} else {
		t.Logf("IssueLease still refuses independently (%v) — the finding above is a restore-time bug, not immediate minting", mintErr)
	}
}
