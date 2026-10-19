package core

// project_delete_machine_suspend_test.go — PROJECT-SUSPEND-1 (#3433).
//
// Decision (Andrei, 2026-10-17, option a): soft-deleting a project SUSPENDS the
// machine identities whose only live roles are in that project; restoring the
// project re-activates exactly the identities that cascade suspended, never one an
// admin suspended on purpose. Identities holding a role in another live project keep
// working (their grants in the deleted project already stop applying).
//
// Before the fix, a machine token of a soft-deleted project kept authenticating
// (AUTHZ-WALKS-HTTP-1's dead-credential walk, awDeadOpen["machine_token_project_deleted"]):
// the cascade never touched machine_identities.
//
// The cases, each one machine identity in one world (SQLite, and Postgres when
// KEYORIX_TEST_PG_DSN is set):
//
//	only        home doomed, role in doomed                    suspended, restored
//	noRole      home doomed, no role at all                    suspended, restored
//	foreign     home live, its only role in doomed (raw row)   suspended, restored
//	deadElse    home doomed, roles in doomed + an already-deleted project
//	                                                           suspended, restored
//	elsewhere   home doomed, roles in doomed + a live project  untouched
//	foreignNone home live, no role                             untouched
//	manual      home doomed, admin-suspended BEFORE the delete stays suspended
//	touched     cascade-suspended, then an admin re-activates and suspends it again
//	            during the deletion window                     stays suspended
//	revoked     home doomed, revoked before the delete         stays revoked
//	oldBinary   cascade-suspended, then re-activated and suspended by a binary that does
//	            not know the marker (marker left, updated_at moved) stays suspended
//
// Plus: restoring a DIFFERENT project during the window re-activates none of them.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type psMachine struct {
	m   *models.MachineIdentity
	raw string
}

func psMint(t *testing.T, w *c4World, home uint, name string, roleProjects ...uint) psMachine {
	t.Helper()
	ctx := context.Background()
	m, err := w.core.CreateMachineIdentity(ctx, home, w.name(name), MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	raw := machineTokenPrefix + w.name("ps-token-"+name)
	require.NoError(t, w.db.Create(&models.MachineIdentityCredential{
		MachineIdentityID: m.ID, Name: name, TokenHash: sha256Hex(raw), TokenPrefix: raw[:len(machineTokenPrefix)+4],
	}).Error)
	if len(roleProjects) > 0 {
		r := w.role(false, w.permission(w.name("ps.perm")))
		for _, pid := range roleProjects {
			// Raw rows: core only grants in the home project, but storage can hold
			// any scope, and the rule is about the rows, not about how they got there.
			require.NoError(t, w.db.Create(&models.MachineIdentityRole{MachineIdentityID: m.ID, RoleID: r.ID, ProjectID: pid}).Error)
		}
	}
	return psMachine{m: m, raw: raw}
}

func psState(t *testing.T, db *gorm.DB, id uint) string {
	t.Helper()
	var m models.MachineIdentity
	require.NoError(t, db.First(&m, id).Error)
	return m.State
}

// psCascadeEvents counts the audit events of eventType about machine identity id
// that name the project cascade as the reason, and checks each one's actor.
func psCascadeEvents(t *testing.T, db *gorm.DB, eventType string, id, actor uint, reason string) int {
	t.Helper()
	var evs []models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", eventType).Find(&evs).Error)
	n := 0
	for _, e := range evs {
		if !strings.Contains(e.Description, reason) || !strings.Contains(e.Description, psIDTag(id)) {
			continue
		}
		n++
		require.NotNil(t, e.UserID, "%s for machine %d must name the acting admin", eventType, id)
		assert.Equal(t, actor, *e.UserID, "%s for machine %d: actor", eventType, id)
	}
	return n
}

func psIDTag(id uint) string { return fmt.Sprintf("machine identity %d;", id) }

func TestDeleteProject_SuspendsMachineIdentitiesHeldOnlyThere(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) { psDeleteRestore(t, backend) })
	}
}

func psDeleteRestore(t *testing.T, backend string) {
	w := newC4World(t, backend)
	c, db, ctx := w.core, w.db, context.Background()
	admin := w.user()

	doomed, live, dead := w.project(), w.project(), w.project()
	require.NoError(t, c.storage.DeleteProject(ctx, dead.ID)) // already deleted before the case under test

	cases := map[string]psMachine{
		"only":        psMint(t, w, doomed.ID, "only", doomed.ID),
		"noRole":      psMint(t, w, doomed.ID, "norole"),
		"foreign":     psMint(t, w, live.ID, "foreign", doomed.ID),
		"deadElse":    psMint(t, w, doomed.ID, "deadelse", doomed.ID, dead.ID),
		"elsewhere":   psMint(t, w, doomed.ID, "elsewhere", doomed.ID, live.ID),
		"foreignNone": psMint(t, w, live.ID, "foreignnone"),
		"manual":      psMint(t, w, doomed.ID, "manual", doomed.ID),
		"touched":     psMint(t, w, doomed.ID, "touched", doomed.ID),
		"revoked":     psMint(t, w, doomed.ID, "revoked", doomed.ID),
		"oldBinary":   psMint(t, w, doomed.ID, "oldbinary", doomed.ID),
	}
	for name, pm := range cases {
		_, _, _, _, err := c.ValidateMachineToken(ctx, pm.raw)
		require.NoError(t, err, "%s: live token must authenticate before the delete", name)
	}
	_, err := c.TransitionMachineIdentity(ctx, doomed.ID, cases["manual"].m.ID, MachineSuspended, admin.ID)
	require.NoError(t, err)
	_, err = c.TransitionMachineIdentity(ctx, doomed.ID, cases["revoked"].m.ID, MachineRevoked, admin.ID)
	require.NoError(t, err)

	require.NoError(t, psDeleteProject(c, ctx, admin.ID, doomed.ID, true))

	cascaded := []string{"only", "noRole", "foreign", "deadElse", "touched", "oldBinary"}
	wantAfterDelete := map[string]string{
		"only": MachineSuspended, "noRole": MachineSuspended, "foreign": MachineSuspended,
		"deadElse": MachineSuspended, "touched": MachineSuspended, "oldBinary": MachineSuspended,
		"elsewhere": MachineActive, "foreignNone": MachineActive,
		"manual": MachineSuspended, "revoked": MachineRevoked,
	}
	for name, want := range wantAfterDelete {
		pm := cases[name]
		assert.Equal(t, want, psState(t, db, pm.m.ID), "%s after project delete", name)
		_, _, _, _, verr := c.ValidateMachineToken(ctx, pm.raw)
		if want == MachineActive {
			assert.NoError(t, verr, "%s: an identity with a live role elsewhere keeps authenticating", name)
		} else {
			assert.ErrorIs(t, verr, ErrMachineIdentityNotActive, "%s: token must stop authenticating", name)
		}
	}
	for _, name := range cascaded {
		assert.Equal(t, 1, psCascadeEvents(t, db, "machine_identity.suspended", cases[name].m.ID, admin.ID, "project soft-delete"),
			"%s: exactly one suspension event naming the project soft-delete, actor = deleting admin", name)
	}
	for _, name := range []string{"elsewhere", "foreignNone", "manual", "revoked"} {
		assert.Zero(t, psCascadeEvents(t, db, "machine_identity.suspended", cases[name].m.ID, admin.ID, "project soft-delete"),
			"%s: the cascade must not suspend (or claim to suspend) it", name)
	}

	// An admin acts on a cascade-suspended identity during the deletion window: from
	// then on it is the admin's decision, not the cascade's, and restore leaves it.
	_, err = c.TransitionMachineIdentity(ctx, doomed.ID, cases["touched"].m.ID, MachineActive, admin.ID)
	require.NoError(t, err)
	_, err = c.TransitionMachineIdentity(ctx, doomed.ID, cases["touched"].m.ID, MachineSuspended, admin.ID)
	require.NoError(t, err)
	var touched models.MachineIdentity
	require.NoError(t, db.First(&touched, cases["touched"].m.ID).Error)
	assert.Zero(t, touched.CascadeSuspendedProjectID, "an explicit transition clears the cascade marker")
	assert.Nil(t, touched.CascadeSuspendedAt)

	// The same two writes by an older binary, which does not know the marker columns:
	// the marker stays, updated_at moves.
	for _, st := range []string{MachineActive, MachineSuspended} {
		require.NoError(t, db.Model(&models.MachineIdentity{}).Where("id = ?", cases["oldBinary"].m.ID).
			UpdateColumns(map[string]any{"state": st, "updated_at": time.Now().Add(time.Second)}).Error)
	}

	// Restoring a different project re-activates nothing of this one's.
	bystander := w.project()
	psMint(t, w, bystander.ID, "bystander", bystander.ID)
	require.NoError(t, psDeleteProject(c, ctx, admin.ID, bystander.ID, true))
	require.NoError(t, c.RestoreProject(ctx, admin.ID, bystander.ID))
	for _, name := range cascaded {
		assert.Equal(t, MachineSuspended, psState(t, db, cases[name].m.ID), "%s: another project's restore must not re-activate it", name)
	}

	require.NoError(t, c.RestoreProject(ctx, admin.ID, doomed.ID))

	restored := []string{"only", "noRole", "foreign", "deadElse"}
	wantAfterRestore := map[string]string{
		"only": MachineActive, "noRole": MachineActive, "foreign": MachineActive, "deadElse": MachineActive,
		"elsewhere": MachineActive, "foreignNone": MachineActive,
		"manual": MachineSuspended, "touched": MachineSuspended, "revoked": MachineRevoked,
		"oldBinary": MachineSuspended,
	}
	for name, want := range wantAfterRestore {
		pm := cases[name]
		assert.Equal(t, want, psState(t, db, pm.m.ID), "%s after project restore", name)
		_, _, _, _, verr := c.ValidateMachineToken(ctx, pm.raw)
		if want == MachineActive {
			assert.NoError(t, verr, "%s: restored identity authenticates again", name)
		} else {
			assert.Error(t, verr, "%s: restore must not re-activate an identity it did not suspend", name)
		}
	}
	for _, name := range restored {
		assert.Equal(t, 1, psCascadeEvents(t, db, "machine_identity.activated", cases[name].m.ID, admin.ID, "project restore"),
			"%s: exactly one re-activation event naming the project restore", name)
	}
	for _, name := range []string{"manual", "touched", "revoked", "elsewhere", "foreignNone", "oldBinary"} {
		assert.Zero(t, psCascadeEvents(t, db, "machine_identity.activated", cases[name].m.ID, admin.ID, "project restore"), name)
	}

	// A second delete/restore round trip behaves the same (the marker of the first
	// round must not leak into the second).
	require.NoError(t, psDeleteProject(c, ctx, admin.ID, doomed.ID, true))
	assert.Equal(t, MachineSuspended, psState(t, db, cases["only"].m.ID))
	require.NoError(t, c.RestoreProject(ctx, admin.ID, doomed.ID))
	assert.Equal(t, MachineActive, psState(t, db, cases["only"].m.ID))
	assert.Equal(t, MachineSuspended, psState(t, db, cases["touched"].m.ID))
}

// The non-force path runs the same cascade: an empty project suspends its
// identities; a project the guard refuses to delete suspends nothing.
func TestDeleteProject_NonForce_SuspendsOnlyWhenDeleted(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			c, db, ctx := w.core, w.db, context.Background()
			admin := w.user()

			blocked := w.project()
			env := w.env(blocked.ID)
			require.NoError(t, db.Create(&models.SecretNode{ProjectID: blocked.ID, EnvironmentID: env.ID, Name: w.name("s"), IsSecret: true, Type: "kv", Status: "active"}).Error)
			kept := psMint(t, w, blocked.ID, "kept", blocked.ID)
			err := psDeleteProject(c, ctx, admin.ID, blocked.ID, false)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "secret(s)")
			assert.Equal(t, MachineActive, psState(t, db, kept.m.ID), "a refused delete must not suspend anything")

			empty := w.project()
			gone := psMint(t, w, empty.ID, "gone", empty.ID)
			require.NoError(t, psDeleteProject(c, ctx, admin.ID, empty.ID, false))
			assert.Equal(t, MachineSuspended, psState(t, db, gone.m.ID))
		})
	}
}

// The suspension and its audit events commit with the cascade or not at all: a fault
// in the machine-identity step leaves the project live and its identities untouched,
// with no suspension event; a fault in the restore after the re-activation leaves the
// project deleted and its identities suspended, with no re-activation event.
func TestDeleteProject_MachineSuspendStepIsAtomicWithTheCascade(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			db, ctx := w.db, context.Background()
			admin := w.user()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)

			p := w.project()
			pm := psMint(t, w, p.ID, "atomic", p.ID)

			faulty.Arm(&faultstorage.FaultSpec{Method: "SuspendMachineIdentitiesForDeletedProject", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			require.Error(t, psDeleteProject(c, ctx, admin.ID, p.ID, true))
			require.True(t, faulty.Fired(), "the fault must be reached")
			_, err := w.core.storage.GetProject(ctx, p.ID)
			require.NoError(t, err, "a failed machine-identity step must roll the project delete back")
			assert.Equal(t, MachineActive, psState(t, db, pm.m.ID))
			assert.Zero(t, psCascadeEvents(t, db, "machine_identity.suspended", pm.m.ID, admin.ID, "project soft-delete"))

			faulty.Arm(nil)
			require.NoError(t, psDeleteProject(c, ctx, admin.ID, p.ID, true))
			require.Equal(t, MachineSuspended, psState(t, db, pm.m.ID))

			faulty.Arm(&faultstorage.FaultSpec{Method: "RestoreProject", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			require.Error(t, c.RestoreProject(ctx, admin.ID, p.ID))
			require.True(t, faulty.Fired())
			assert.Equal(t, MachineSuspended, psState(t, db, pm.m.ID), "a failed restore must not re-activate anything")
			assert.Zero(t, psCascadeEvents(t, db, "machine_identity.activated", pm.m.ID, admin.ID, "project restore"))

			faulty.Arm(nil)
			require.NoError(t, c.RestoreProject(ctx, admin.ID, p.ID))
			assert.Equal(t, MachineActive, psState(t, db, pm.m.ID))
			assert.Equal(t, 1, psCascadeEvents(t, db, "machine_identity.activated", pm.m.ID, admin.ID, "project restore"))
		})
	}
}

func psDeleteProject(c *KeyorixCore, ctx context.Context, actorID, id uint, force bool) error {
	return c.DeleteProject(ctx, actorID, id, force)
}
