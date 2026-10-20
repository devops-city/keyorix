// store_s3_local2_test.go — additional coverage for local_mfa, local_machine_credentials,
// local_machine_identities, local_rotation_policies, local_memberships (stale count),
// local_notifications (escalation), local_secret_dependencies, and local_rbac
// (basic CRUD operations only).
package store

import (
	"context"
	"testing"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// local_mfa
// ---------------------------------------------------------------------------

func newMFAStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "mfa_"+t.Name(),
		&models.MFASecret{}, &models.MFARecoveryCode{}, &models.MFAChallenge{}, &models.User{})
}

func TestMFA_UpsertGetActivate(t *testing.T) {
	ctx := context.Background()
	ls := newMFAStore(t)

	// Upsert (insert).
	require.NoError(t, ls.UpsertMFASecret(ctx, &models.MFASecret{
		UserID: 1, SecretEnc: []byte("enc"), SecretMeta: []byte("meta"), Activated: false,
	}))

	// Get.
	got, err := ls.GetMFASecret(ctx, 1)
	require.NoError(t, err)
	assert.False(t, got.Activated)

	// Activate: a stale ciphertext matches nothing (#2655); the current one does.
	matched, err := ls.ActivateMFASecret(ctx, 1, []byte("stale-enc"))
	require.NoError(t, err)
	assert.False(t, matched)
	got1, err := ls.GetMFASecret(ctx, 1)
	require.NoError(t, err)
	assert.False(t, got1.Activated, "a mismatched ciphertext must not activate the secret")
	matched, err = ls.ActivateMFASecret(ctx, 1, []byte("enc"))
	require.NoError(t, err)
	assert.True(t, matched)
	got2, err := ls.GetMFASecret(ctx, 1)
	require.NoError(t, err)
	assert.True(t, got2.Activated)

	// Get — not found.
	_, err = ls.GetMFASecret(ctx, 99)
	require.Error(t, err)

	// Upsert over the now-ACTIVATED row is refused and writes nothing (#2692);
	// this used to assert the replace, which was the bug. Replacing a pending
	// row is covered by TestUpsertMFASecret_NeverReplacesActivatedSecret.
	err = ls.UpsertMFASecret(ctx, &models.MFASecret{
		UserID: 1, SecretEnc: []byte("enc2"), SecretMeta: []byte("meta2"), Activated: false,
	})
	require.ErrorIs(t, err, coreStorage.ErrMFASecretActivated)
	got3, err := ls.GetMFASecret(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("enc"), got3.SecretEnc)
	assert.True(t, got3.Activated)
}

func TestMFA_MarkTOTPStepUsed(t *testing.T) {
	ctx := context.Background()
	ls := newMFAStore(t)

	require.NoError(t, ls.UpsertMFASecret(ctx, &models.MFASecret{
		UserID: 2, SecretEnc: []byte("enc"), Activated: true,
	}))

	// First use of step 100 → accepted.
	ok, err := ls.MarkTOTPStepUsed(ctx, 2, 100)
	require.NoError(t, err)
	assert.True(t, ok)

	// Same step again → rejected (replay).
	ok2, err := ls.MarkTOTPStepUsed(ctx, 2, 100)
	require.NoError(t, err)
	assert.False(t, ok2)

	// Lower step → rejected.
	ok3, err := ls.MarkTOTPStepUsed(ctx, 2, 99)
	require.NoError(t, err)
	assert.False(t, ok3)

	// Higher step → accepted.
	ok4, err := ls.MarkTOTPStepUsed(ctx, 2, 101)
	require.NoError(t, err)
	assert.True(t, ok4)
}

func TestMFA_RecoveryCodes(t *testing.T) {
	ctx := context.Background()
	ls := newMFAStore(t)

	// Empty list → no-op.
	require.NoError(t, ls.CreateMFARecoveryCodes(ctx, 3, nil))
	require.NoError(t, ls.CreateMFARecoveryCodes(ctx, 3, []string{}))

	// Create recovery codes.
	require.NoError(t, ls.CreateMFARecoveryCodes(ctx, 3, []string{"h1", "h2", "h3"}))

	// Count unused.
	n, err := ls.CountUnusedMFARecoveryCodes(ctx, 3)
	require.NoError(t, err)
	assert.Equal(t, 3, n)

	// Consume one.
	consumed, err := ls.ConsumeMFARecoveryCode(ctx, 3, "h1", time.Now())
	require.NoError(t, err)
	assert.True(t, consumed)

	// Replay the same code → not consumed again.
	consumed2, err := ls.ConsumeMFARecoveryCode(ctx, 3, "h1", time.Now())
	require.NoError(t, err)
	assert.False(t, consumed2)

	// Count unused is now 2.
	n2, err := ls.CountUnusedMFARecoveryCodes(ctx, 3)
	require.NoError(t, err)
	assert.Equal(t, 2, n2)

	// Delete all recovery codes.
	require.NoError(t, ls.DeleteMFARecoveryCodes(ctx, 3))
	n3, err := ls.CountUnusedMFARecoveryCodes(ctx, 3)
	require.NoError(t, err)
	assert.Equal(t, 0, n3)
}

func TestMFA_SetUserMFAEnabled(t *testing.T) {
	ctx := context.Background()
	ls := newMFAStore(t)

	// Create a user.
	require.NoError(t, ls.db.Create(&models.User{Username: "mfa-user", UsernameFolded: "mfa-user", Email: "mfa@example.com", EmailFolded: "mfa@example.com"}).Error)
	var u models.User
	require.NoError(t, ls.db.Where("username = ?", "mfa-user").First(&u).Error)

	require.NoError(t, ls.SetUserMFAEnabled(ctx, u.ID, true))
	require.NoError(t, ls.db.First(&u, u.ID).Error)
	assert.True(t, u.MFAEnabled)

	require.NoError(t, ls.SetUserMFAEnabled(ctx, u.ID, false))
	require.NoError(t, ls.db.First(&u, u.ID).Error)
	assert.False(t, u.MFAEnabled)
}

func TestMFA_DeleteMFAForUser(t *testing.T) {
	ctx := context.Background()
	ls := newMFAStore(t)

	require.NoError(t, ls.UpsertMFASecret(ctx, &models.MFASecret{
		UserID: 10, SecretEnc: []byte("enc"), Activated: true,
	}))
	require.NoError(t, ls.CreateMFARecoveryCodes(ctx, 10, []string{"code1", "code2"}))

	require.NoError(t, ls.DeleteMFAForUser(ctx, 10))

	_, err := ls.GetMFASecret(ctx, 10)
	require.Error(t, err, "MFA secret should be deleted")
	n, err := ls.CountUnusedMFARecoveryCodes(ctx, 10)
	require.NoError(t, err)
	assert.Zero(t, n)
}

func TestMFA_Challenges(t *testing.T) {
	ctx := context.Background()
	ls := newMFAStore(t)

	now := time.Now()
	exp := now.Add(5 * time.Minute)

	ch := &models.MFAChallenge{
		UserID: 5, TokenHash: "hash-ch1", ExpiresAt: exp,
	}
	require.NoError(t, ls.CreateMFAChallenge(ctx, ch))

	// GetActiveMFAChallenge.
	got, err := ls.GetActiveMFAChallenge(ctx, "hash-ch1", now)
	require.NoError(t, err)
	assert.Equal(t, ch.ID, got.ID)

	// GetActiveMFAChallenge — not found (wrong hash).
	_, err = ls.GetActiveMFAChallenge(ctx, "nope", now)
	require.Error(t, err)

	// ConsumeMFAChallenge.
	consumed, err := ls.ConsumeMFAChallenge(ctx, "hash-ch1", now)
	require.NoError(t, err)
	assert.Equal(t, ch.ID, consumed.ID)

	// Consuming again → error (already used).
	_, err = ls.ConsumeMFAChallenge(ctx, "hash-ch1", now)
	require.Error(t, err)

	// Expired challenge → not found.
	expiredCh := &models.MFAChallenge{
		UserID: 5, TokenHash: "hash-ch2", ExpiresAt: now.Add(-time.Minute),
	}
	require.NoError(t, ls.CreateMFAChallenge(ctx, expiredCh))
	_, err = ls.GetActiveMFAChallenge(ctx, "hash-ch2", now)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_credentials
// ---------------------------------------------------------------------------

func newMachCredStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "mach_cred_"+t.Name(),
		&models.MachineIdentity{}, &models.MachineIdentityCredential{},
		&models.MachineIdentityRole{}, &models.MachineIdentityOIDCBinding{},
		&models.Role{}, &models.Project{}, &models.Environment{})
}

func TestMachineIdentityCredential_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newMachCredStore(t)

	// Create machine.
	m, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 1, Name: "ci-runner", IdentityType: "ci", State: "active",
	})
	require.NoError(t, err)

	// Create credential.
	cred, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: m.ID, Name: "ci-token", TokenHash: "hash-ci", TokenPrefix: "kx_machine_ci",
	})
	require.NoError(t, err)
	assert.NotZero(t, cred.ID)

	// GetByHash.
	got, err := ls.GetMachineIdentityCredentialByHash(ctx, "hash-ci")
	require.NoError(t, err)
	assert.Equal(t, cred.ID, got.ID)

	// GetByHash — not found.
	_, err = ls.GetMachineIdentityCredentialByHash(ctx, "nope")
	require.Error(t, err)

	// GetByID.
	gotID, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, gotID.ID)

	// GetByID — not found.
	_, err = ls.GetMachineIdentityCredentialByID(ctx, 99999)
	require.Error(t, err)

	// List.
	list, err := ls.ListMachineIdentityCredentials(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// ListActive — one non-revoked.
	active, err := ls.ListActiveMachineIdentityCredentials(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 1)

	// Classify (#2696: the only mutation this model has besides touch/revoke —
	// column-scoped and conditional on the classification the caller read).
	matched, err := ls.SetMachineIdentityCredentialClassification(ctx, cred.ID, cred.Classification, "internal")
	require.NoError(t, err)
	require.True(t, matched)
	got2, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, "internal", got2.Classification)
	// A stale `from` value must not match, so a concurrent classifier's value is
	// never clobbered.
	matched, err = ls.SetMachineIdentityCredentialClassification(ctx, cred.ID, "public", "restricted")
	require.NoError(t, err)
	require.False(t, matched)
	got2b, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, "internal", got2b.Classification)

	// Touch.
	usedAt := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, ls.TouchMachineIdentityCredential(ctx, cred.ID, usedAt, 30*time.Second))
	got3, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.NotNil(t, got3.LastUsedAt)

	// Revoke.
	require.NoError(t, ls.RevokeMachineIdentityCredential(ctx, m.ProjectID, cred.ID))
	got4, err := ls.GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.True(t, got4.Revoked)

	// Revoke non-existent credential → not found error.
	err = ls.RevokeMachineIdentityCredential(ctx, m.ProjectID, 99999)
	require.Error(t, err)

	// ListActive → now empty.
	active2, err := ls.ListActiveMachineIdentityCredentials(ctx)
	require.NoError(t, err)
	assert.Empty(t, active2)
}

func TestMachineIdentityCredential_CountByClassification(t *testing.T) {
	ctx := context.Background()
	ls := newMachCredStore(t)

	for _, c := range []struct {
		hash, class string
	}{
		{"h1", "confidential"}, {"h2", "confidential"}, {"h3", ""},
	} {
		_, err := ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: 1, Name: c.hash, TokenHash: c.hash,
			TokenPrefix: "kx_machine_" + c.hash, Classification: c.class,
		})
		require.NoError(t, err)
	}

	m, err := ls.CountMachineIdentityCredentialsByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, m["confidential"])
	assert.Equal(t, 1, m[""])
}

func TestMachineIdentityRoles(t *testing.T) {
	ctx := context.Background()
	ls := newMachCredStore(t)

	// Create role.
	role := &models.Role{Name: "reader", Description: "read-only"}
	require.NoError(t, ls.db.Create(role).Error)

	// Create machine.
	m, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 1, Name: "worker", IdentityType: "ci", State: "active",
	})
	require.NoError(t, err)

	scope := coreStorage.Scope{ProjectID: 1, EnvironmentID: 0}

	// Assign role.
	require.NoError(t, ls.AssignMachineRole(ctx, m.ID, role.ID, scope))

	// Assign same role again → error.
	err = ls.AssignMachineRole(ctx, m.ID, role.ID, scope)
	require.Error(t, err)

	// GetMachineRoleIDsAt.
	ids, err := ls.GetMachineRoleIDsAt(ctx, m.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, ids, role.ID)

	// GetMachineRoles.
	roles, err := ls.GetMachineRoles(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, roles, 1)

	// RemoveMachineRole.
	require.NoError(t, ls.RemoveMachineRole(ctx, m.ID, role.ID, scope))

	// Remove again → error.
	err = ls.RemoveMachineRole(ctx, m.ID, role.ID, scope)
	require.Error(t, err)

	// Roles now empty.
	ids2, err := ls.GetMachineRoleIDsAt(ctx, m.ID, scope)
	require.NoError(t, err)
	assert.Empty(t, ids2)
}

func TestMachineIdentityOIDCBindings(t *testing.T) {
	ctx := context.Background()
	ls := newMachCredStore(t)

	m, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 1, Name: "k8s-sa", IdentityType: "k8s", State: "active",
	})
	require.NoError(t, err)

	// Create OIDC binding.
	b, err := ls.CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: m.ID, Issuer: "https://accounts.example.com", Subject: "sa:default:ns1", CreatedBy: 1,
	})
	require.NoError(t, err)
	assert.NotZero(t, b.ID)

	// GetByOIDCSubject.
	got, err := ls.GetMachineByOIDCSubject(ctx, "https://accounts.example.com", "sa:default:ns1")
	require.NoError(t, err)
	assert.Equal(t, m.ID, got.ID)

	// GetByOIDCSubject — not found.
	_, err = ls.GetMachineByOIDCSubject(ctx, "nope", "nope")
	require.Error(t, err)

	// ListOIDCBindings.
	bindings, err := ls.ListOIDCBindings(ctx, m.ID)
	require.NoError(t, err)
	assert.Len(t, bindings, 1)

	// GetOIDCBindingByID.
	gotB, err := ls.GetOIDCBindingByID(ctx, b.ID)
	require.NoError(t, err)
	assert.Equal(t, b.ID, gotB.ID)

	// GetOIDCBindingByID — not found.
	_, err = ls.GetOIDCBindingByID(ctx, 99999)
	require.Error(t, err)

	// DeleteOIDCBinding.
	require.NoError(t, ls.DeleteOIDCBinding(ctx, b.ID))

	// Delete again → not found.
	err = ls.DeleteOIDCBinding(ctx, b.ID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_machine_identities
// ---------------------------------------------------------------------------

func TestMachineIdentity_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newMachCredStore(t)

	// Create.
	m, err := ls.CreateMachineIdentity(ctx, &models.MachineIdentity{
		ProjectID: 2, Name: "svc-api", IdentityType: "service", State: "active",
	})
	require.NoError(t, err)
	assert.NotZero(t, m.ID)

	// Get.
	got, err := ls.GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, "svc-api", got.Name)

	// Get — not found.
	_, err = ls.GetMachineIdentity(ctx, 99999)
	require.Error(t, err)

	// LockMachineIdentityForUpdate (SQLite path).
	locked, err := ls.LockMachineIdentityForUpdate(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, m.ID, locked.ID)

	// LockMachineIdentityForUpdate — not found.
	_, err = ls.LockMachineIdentityForUpdate(ctx, 99999)
	require.Error(t, err)

	// Update (via TransitionMachineIdentityState, which persists the full row).
	m.Description = "updated"
	m.State = "suspended"
	won, err := ls.TransitionMachineIdentityState(ctx, m, "active")
	require.NoError(t, err)
	assert.True(t, won)
	got2, err := ls.GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated", got2.Description)
	assert.Equal(t, "suspended", got2.State)

	// Already transitioned → won = false.
	m.State = "revoked"
	won2, err := ls.TransitionMachineIdentityState(ctx, m, "active")
	require.NoError(t, err)
	assert.False(t, won2, "state is now suspended, not active")

	// ListMachineIdentities.
	list, err := ls.ListMachineIdentities(ctx, 2)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// ListAllMachineIdentities.
	all, err := ls.ListAllMachineIdentities(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	// CountMachineIdentitiesByClassification.
	cm, err := ls.CountMachineIdentitiesByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, cm[""])
}

func TestCountStaleMachineIdentitiesByProject(t *testing.T) {
	ctx := context.Background()
	ls := newMachCredStore(t)

	now := time.Now()
	old := now.Add(-30 * 24 * time.Hour)

	// Project 1: active machine not seen in 30 days.
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ProjectID: 1, Name: "stale", State: "active", CreatedAt: old,
	}).Error)
	// Project 1: active machine seen recently.
	seen := now.Add(-time.Hour)
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ProjectID: 1, Name: "fresh", State: "active", CreatedAt: old, LastSeenAt: &seen,
	}).Error)
	// Project 2: suspended machine — not counted.
	require.NoError(t, ls.db.Create(&models.MachineIdentity{
		ProjectID: 2, Name: "suspended", State: "suspended", CreatedAt: old,
	}).Error)

	// Empty input.
	empty, err := ls.CountStaleMachineIdentitiesByProject(ctx, nil, now.Add(-7*24*time.Hour))
	require.NoError(t, err)
	assert.Empty(t, empty)

	counts, err := ls.CountStaleMachineIdentitiesByProject(ctx, []uint{1, 2}, now.Add(-7*24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, counts[1], "only the stale active machine counts")
	assert.Equal(t, 0, counts[2], "suspended machines are excluded")
}

// ---------------------------------------------------------------------------
// local_rotation_policies
// ---------------------------------------------------------------------------

func newRotationPoliciesStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "rot_pol_"+t.Name(), &models.RotationPolicy{})
}

func TestRotationPolicies_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newRotationPoliciesStore(t)

	projID := uint(1)
	envID := uint(2)

	// Create.
	require.NoError(t, ls.CreateRotationPolicy(ctx, &models.RotationPolicy{
		Name: "30-day", Scope: "environment", ProjectID: &projID, EnvironmentID: &envID,
		IntervalDays: 30, CreatedBy: "admin",
	}))
	require.NoError(t, ls.CreateRotationPolicy(ctx, &models.RotationPolicy{
		Name: "90-day", Scope: "project", ProjectID: &projID,
		IntervalDays: 90, CreatedBy: "admin",
	}))

	// Get by ID.
	var all []*models.RotationPolicy
	require.NoError(t, ls.db.Find(&all).Error)
	require.Len(t, all, 2)

	got, err := ls.GetRotationPolicy(ctx, all[0].ID)
	require.NoError(t, err)
	assert.Equal(t, all[0].Name, got.Name)

	// Get not found.
	_, err = ls.GetRotationPolicy(ctx, 99999)
	require.Error(t, err)

	// List — no filters.
	list, err := ls.ListRotationPolicies(ctx, nil, nil)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// List — project filter.
	list2, err := ls.ListRotationPolicies(ctx, &projID, nil)
	require.NoError(t, err)
	assert.Len(t, list2, 2)

	// List — environment filter.
	list3, err := ls.ListRotationPolicies(ctx, nil, &envID)
	require.NoError(t, err)
	assert.Len(t, list3, 1)

	// Update.
	matched, err := ls.UpdateRotationPolicyFields(ctx, all[0].ID, coreStorage.RotationPolicyFieldUpdate{
		Name: all[0].Name, IntervalDays: 45, AlertDaysBefore: all[0].AlertDaysBefore, IsActive: true,
	}, time.Now())
	require.NoError(t, err)
	require.True(t, matched)
	got2, err := ls.GetRotationPolicy(ctx, all[0].ID)
	require.NoError(t, err)
	assert.Equal(t, 45, got2.IntervalDays)

	// Delete.
	require.NoError(t, ls.DeleteRotationPolicy(ctx, all[0].ID))
	_, err = ls.GetRotationPolicy(ctx, all[0].ID)
	require.Error(t, err)

	// #2700: the policy is SOFT-deleted, so an update must not clear deleted_at
	// and bring it back active — the former Save's upsert fallback did exactly
	// that.
	matched, err = ls.UpdateRotationPolicyFields(ctx, all[0].ID, coreStorage.RotationPolicyFieldUpdate{
		Name: "zombie", IntervalDays: 45, IsActive: true,
	}, time.Now())
	require.NoError(t, err)
	require.False(t, matched, "a soft-deleted policy must not be resurrected by an update")
	_, err = ls.GetRotationPolicy(ctx, all[0].ID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_rbac — basic coverage for uncovered functions
// ---------------------------------------------------------------------------

func newRBACStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "rbac_"+t.Name(),
		&models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.User{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		// MachineIdentityRole/ConnectRefGrant: DeleteRole's cascade (SESSION-AT
		// AT1 row 2) deletes from every RoleID-referencing table, so any
		// fixture exercising a real (non-404) DeleteRole needs all five.
		&models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{},
		// SystemMetadata: AssignPermissionToRole/RemovePermissionFromRole/
		// DeleteRole bump the PERF-3 PR-2 role_permissions cache generation
		// (a system_metadata row) in the same transaction as the real write.
		&models.SystemMetadata{})
}

func TestRBAC_RolesAndPermissions(t *testing.T) {
	ctx := context.Background()
	ls := newRBACStore(t)

	// CreateRole.
	viewerName, err := identity.NewFoldedName("viewer")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, viewerName, "read-only")
	require.NoError(t, err)
	assert.NotZero(t, role.ID)

	// GetRole.
	got, err := ls.GetRole(ctx, role.ID)
	require.NoError(t, err)
	assert.Equal(t, "viewer", got.Name)

	// GetRole — not found.
	_, err = ls.GetRole(ctx, 99999)
	require.Error(t, err)

	// GetRoleByName.
	gotN, err := ls.GetRoleByName(ctx, "viewer")
	require.NoError(t, err)
	assert.Equal(t, role.ID, gotN.ID)

	// GetRoleByName — not found.
	_, err = ls.GetRoleByName(ctx, "nope")
	require.Error(t, err)

	// ListRoles.
	roles, err := ls.ListRoles(ctx)
	require.NoError(t, err)
	assert.Len(t, roles, 1)

	// CreatePermission.
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read", Resource: "secrets", Action: "read"})
	require.NoError(t, err)
	assert.NotZero(t, perm.ID)

	// ListPermissions.
	perms, err := ls.ListPermissions(ctx)
	require.NoError(t, err)
	assert.Len(t, perms, 1)

	// AssignPermissionToRole.
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	// GetRolePermissions.
	rolePerms, err := ls.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	assert.Len(t, rolePerms, 1)
	assert.Equal(t, perm.ID, rolePerms[0].ID)

	// RemovePermissionFromRole.
	require.NoError(t, ls.RemovePermissionFromRole(ctx, role.ID, perm.ID))
	rolePerms2, err := ls.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	assert.Empty(t, rolePerms2)

	// UpdateRole.
	role.Description = "updated"
	updated, err := ls.UpdateRole(ctx, role)
	require.NoError(t, err)
	assert.Equal(t, "updated", updated.Description)
}

func TestRBAC_UserRoles(t *testing.T) {
	ctx := context.Background()
	ls := newRBACStore(t)

	// Create role.
	editorName, err := identity.NewFoldedName("editor")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, editorName, "edit")
	require.NoError(t, err)

	// Create user.
	require.NoError(t, ls.db.Create(&models.User{Username: "rbac-user", UsernameFolded: "rbac-user", Email: "rbac@example.com", EmailFolded: "rbac@example.com"}).Error)
	var u models.User
	require.NoError(t, ls.db.Where("username = ?", "rbac-user").First(&u).Error)

	scope := coreStorage.Scope{ProjectID: 1, EnvironmentID: 0}

	// AssignRole.
	require.NoError(t, ls.AssignRole(ctx, u.ID, role.ID, scope))

	// AssignRole — duplicate.
	err = ls.AssignRole(ctx, u.ID, role.ID, scope)
	require.Error(t, err)

	// GetUserRoleIDsAt.
	ids, err := ls.GetUserRoleIDsAt(ctx, u.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, ids, role.ID)

	// GetUserRoles.
	userRoles, err := ls.GetUserRoles(ctx, u.ID)
	require.NoError(t, err)
	assert.Len(t, userRoles, 1)

	// RemoveRole.
	require.NoError(t, ls.RemoveRole(ctx, u.ID, role.ID, scope))

	// RemoveRole — not found.
	err = ls.RemoveRole(ctx, u.ID, role.ID, scope)
	require.Error(t, err)

	// Now empty.
	ids2, err := ls.GetUserRoleIDsAt(ctx, u.ID, scope)
	require.NoError(t, err)
	assert.Empty(t, ids2)
}

func TestRBAC_GroupRoles(t *testing.T) {
	ctx := context.Background()
	ls := newRBACStore(t)

	memberName, err := identity.NewFoldedName("member")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, memberName, "member")
	require.NoError(t, err)

	// Create group.
	group, err := ls.CreateGroup(ctx, &models.Group{Name: "eng-team", NameFolded: "eng-team"})
	require.NoError(t, err)
	assert.NotZero(t, group.ID)

	scope := coreStorage.Scope{ProjectID: 1, EnvironmentID: 0}

	// AssignRoleToGroup.
	require.NoError(t, ls.AssignRoleToGroup(ctx, group.ID, role.ID, scope))

	// GetGroupRoles.
	groupRoles, err := ls.GetGroupRoles(ctx, group.ID)
	require.NoError(t, err)
	assert.Len(t, groupRoles, 1)
	assert.Equal(t, role.ID, groupRoles[0].ID)

	// RemoveRoleFromGroup.
	require.NoError(t, ls.RemoveRoleFromGroup(ctx, group.ID, role.ID, scope))

	// Remove again → error.
	err = ls.RemoveRoleFromGroup(ctx, group.ID, role.ID, scope)
	require.Error(t, err)
}

func TestRBAC_UserGroups(t *testing.T) {
	ctx := context.Background()
	ls := newRBACStore(t)

	// Create group.
	group, err := ls.CreateGroup(ctx, &models.Group{Name: "devs", NameFolded: "devs"})
	require.NoError(t, err)

	// Create user.
	require.NoError(t, ls.db.Create(&models.User{Username: "dev1", UsernameFolded: "dev1", Email: "dev1@example.com", EmailFolded: "dev1@example.com"}).Error)
	var u models.User
	require.NoError(t, ls.db.Where("username = ?", "dev1").First(&u).Error)

	// AddUserToGroup (global: projectID=0).
	require.NoError(t, ls.AddUserToGroup(ctx, u.ID, group.ID, 0))

	// AddUserToGroup — idempotent (returns nil for duplicate with same projectID).
	require.NoError(t, ls.AddUserToGroup(ctx, u.ID, group.ID, 0))

	// GetUserGroups.
	groups, err := ls.GetUserGroups(ctx, u.ID)
	require.NoError(t, err)
	assert.Len(t, groups, 1)

	// RemoveUserFromGroup (global: projectID=0).
	require.NoError(t, ls.RemoveUserFromGroup(ctx, u.ID, group.ID, 0))

	// GetUserGroups — empty.
	groups2, err := ls.GetUserGroups(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, groups2)
}

func TestRBAC_DeleteRole(t *testing.T) {
	ctx := context.Background()
	ls := newRBACStore(t)

	tempName, err := identity.NewFoldedName("temp")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, tempName, "temp")
	require.NoError(t, err)

	_, err = ls.DeleteRole(ctx, role.ID)
	require.NoError(t, err)

	_, err = ls.GetRole(ctx, role.ID)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// local_secret_dependencies — uncovered (0%)
// ---------------------------------------------------------------------------

func newSecretDepsStore(t *testing.T) *LocalStorage {
	t.Helper()
	return newStoreS3(t, "sec_deps_"+t.Name(), &models.SecretDependency{})
}

func TestSecretDependencies_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newSecretDepsStore(t)

	// Create.
	dep, err := ls.CreateSecretDependency(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 1, DependsOnSecretID: 2,
	})
	require.NoError(t, err)
	assert.NotZero(t, dep.ID)

	// ListSecretDependenciesForProject.
	list, err := ls.ListSecretDependenciesForProject(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// ListSecretDependenciesForProjectForUpdate (SQLite path).
	list2, err := ls.ListSecretDependenciesForProjectForUpdate(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list2, 1)

	// Get.
	got, err := ls.GetSecretDependency(ctx, dep.ID)
	require.NoError(t, err)
	assert.Equal(t, dep.ID, got.ID)

	// Get not found.
	_, err = ls.GetSecretDependency(ctx, 99999)
	require.Error(t, err)

	// CreateSecretDependencyExclusive — duplicate.
	_, err = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 1, DependsOnSecretID: 2,
	})
	require.Error(t, err, "duplicate dependency must be rejected")

	// CreateSecretDependencyExclusive — cycle.
	_, err = ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 2, DependsOnSecretID: 1,
	})
	require.Error(t, err, "cycle must be rejected")

	// CreateSecretDependencyExclusive — new valid edge.
	dep2, err := ls.CreateSecretDependencyExclusive(ctx, &models.SecretDependency{
		ProjectID: 1, DependentSecretID: 3, DependsOnSecretID: 4,
	})
	require.NoError(t, err)
	assert.NotZero(t, dep2.ID)

	// Delete.
	require.NoError(t, ls.DeleteSecretDependency(ctx, dep.ID))

	// Delete — not found.
	err = ls.DeleteSecretDependency(ctx, dep.ID)
	require.Error(t, err)

	// Verify project list reduced by 1.
	list3, err := ls.ListSecretDependenciesForProject(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, list3, 1) // dep2 remains
}
